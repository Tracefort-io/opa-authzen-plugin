package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// testDSNEnv names a Postgres DSN for the Postgres conformance run. The
// tests create and drop a schema of their own, so any disposable database
// will do, such as a throwaway local container. Unset skips Postgres.
const testDSNEnv = "AUTHZEN_ARS_TEST_DSN"

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func stores(t *testing.T) map[string]func(t *testing.T) Store {
	out := map[string]func(t *testing.T) Store{
		"memory": func(*testing.T) Store { return NewMemory() },
	}
	if dsn := os.Getenv(testDSNEnv); dsn != "" {
		out["postgres"] = func(t *testing.T) Store {
			t.Helper()
			return openTestPostgres(t, dsn)
		}
	}
	return out
}

var schemaSeq int
var schemaMu sync.Mutex

func openTestPostgres(t *testing.T, dsn string) *Postgres {
	t.Helper()
	schemaMu.Lock()
	schemaSeq++
	schema := fmt.Sprintf("ars_test_%d_%d", os.Getpid(), schemaSeq)
	schemaMu.Unlock()
	ctx := context.Background()
	p, err := OpenPostgres(ctx, dsn, schema, 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = p.pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		p.Close()
	})
	return p
}

func newTask(id string) *Task {
	return &Task{
		ID:           id,
		Status:       StatusPending,
		RequesterIss: "https://idp.example.com",
		RequesterSub: "agent-7",
		Subject:      map[string]any{"type": "user", "id": "alice"},
		Denial:       map[string]any{"evaluation_id": "eval_1"},
		Workflow: Workflow{Steps: []Step{{
			Name:      "manager_approval",
			Required:  1,
			Approvers: []map[string]any{{"type": "user", "id": "manager"}},
		}}},
		Items: []Item{{
			Index:    0,
			Resource: map[string]any{"type": "document", "id": "q4-plan"},
			Action:   map[string]any{"name": "can_read"},
			Status:   StatusPending,
		}},
		ExpiresAt: t0.Add(time.Hour),
		CreatedAt: t0,
	}
}

func newApproval(id, taskID string) *Approval {
	return &Approval{
		ID:                    id,
		TaskID:                taskID,
		Subject:               map[string]any{"type": "user", "id": "alice"},
		Resource:              map[string]any{"type": "document", "id": "q4-plan"},
		Action:                map[string]any{"name": "can_read"},
		BindingContextMembers: []string{"project"},
		Context:               map[string]any{"project": "renewal"},
		ApprovedAt:            t0,
		ApprovedUntil:         t0.Add(24 * time.Hour),
	}
}

func TestStoreConformance(t *testing.T) {
	for name, open := range stores(t) {
		t.Run(name, func(t *testing.T) {
			t.Run("create and get", func(t *testing.T) { testCreateGet(t, open(t)) })
			t.Run("idempotency", func(t *testing.T) { testIdempotency(t, open(t)) })
			t.Run("replay", func(t *testing.T) { testReplay(t, open(t)) })
			t.Run("update and decisions", func(t *testing.T) { testUpdate(t, open(t)) })
			t.Run("list pending", func(t *testing.T) { testListPending(t, open(t)) })
			t.Run("approvals and revocation", func(t *testing.T) { testApprovals(t, open(t)) })
			t.Run("expire due", func(t *testing.T) { testExpire(t, open(t)) })
			t.Run("item steps", func(t *testing.T) { testItemSteps(t, open(t)) })
			t.Run("bulk expiry", func(t *testing.T) { testBulkExpiry(t, open(t)) })
			t.Run("callbacks", func(t *testing.T) { testCallbacks(t, open(t)) })
			t.Run("purge", func(t *testing.T) { testPurge(t, open(t)) })
		})
	}
}

func testCreateGet(t *testing.T, s Store) {
	ctx := context.Background()
	task, existed, err := s.CreateTask(ctx, &NewTask{Task: newTask("arq_1"), JTIs: []JTI{{ID: "j1", Expires: t0.Add(time.Hour)}}}, t0)
	if err != nil || existed || task.ID != "arq_1" {
		t.Fatalf("create: %v %v %v", task, existed, err)
	}
	got, err := s.GetTask(ctx, "arq_1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusPending || got.Subject["id"] != "alice" || len(got.Items) != 1 ||
		got.Items[0].Resource["id"] != "q4-plan" || got.Workflow.Steps[0].Name != "manager_approval" ||
		!got.ExpiresAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if _, err := s.GetTask(ctx, "arq_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func testIdempotency(t *testing.T, s Store) {
	ctx := context.Background()
	idem := Idempotency{Requester: "iss|agent-7", Key: "k1", BodyHash: []byte("h1"), RetainUntil: t0.Add(2 * time.Hour)}
	if _, _, err := s.CreateTask(ctx, &NewTask{Task: newTask("arq_a"), Idempotency: idem, JTIs: []JTI{{ID: "ja"}}}, t0); err != nil {
		t.Fatal(err)
	}
	// Same key and body: the original task, even though the retry carries
	// a different task id and the same token.
	got, existed, err := s.CreateTask(ctx, &NewTask{Task: newTask("arq_b"), Idempotency: idem, JTIs: []JTI{{ID: "ja"}}}, t0)
	if err != nil || !existed || got.ID != "arq_a" {
		t.Fatalf("idempotent retry: %v %v %v", got, existed, err)
	}
	// Same key, different body.
	other := idem
	other.BodyHash = []byte("h2")
	if _, _, err := s.CreateTask(ctx, &NewTask{Task: newTask("arq_c"), Idempotency: other, JTIs: []JTI{{ID: "jc"}}}, t0); !errors.Is(err, ErrDuplicateRequest) {
		t.Fatalf("expected ErrDuplicateRequest, got %v", err)
	}
	// After retention the key is reclaimed.
	got, existed, err = s.CreateTask(ctx, &NewTask{Task: newTask("arq_d"), Idempotency: other, JTIs: []JTI{{ID: "jd"}}}, t0.Add(3*time.Hour))
	if err != nil || existed || got.ID != "arq_d" {
		t.Fatalf("reclaimed key: %v %v %v", got, existed, err)
	}
	// Another requester may use the same key.
	theirs := idem
	theirs.Requester = "iss|agent-8"
	if _, existed, err := s.CreateTask(ctx, &NewTask{Task: newTask("arq_e"), Idempotency: theirs, JTIs: []JTI{{ID: "je"}}}, t0); err != nil || existed {
		t.Fatalf("keys must be scoped to the requester: %v %v", existed, err)
	}
}

func testReplay(t *testing.T, s Store) {
	ctx := context.Background()
	if _, _, err := s.CreateTask(ctx, &NewTask{Task: newTask("arq_1"), JTIs: []JTI{{ID: "same"}}}, t0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateTask(ctx, &NewTask{Task: newTask("arq_2"), JTIs: []JTI{{ID: "same"}}}, t0); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected ErrReplay, got %v", err)
	}
	if _, err := s.GetTask(ctx, "arq_2"); !errors.Is(err, ErrNotFound) {
		t.Fatal("a replayed submission must store nothing")
	}
	// One token on two items of the same submission is a replay too.
	if _, _, err := s.CreateTask(ctx, &NewTask{Task: newTask("arq_3"), JTIs: []JTI{{ID: "twice"}, {ID: "twice"}}}, t0); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected ErrReplay for a repeated token, got %v", err)
	}
}

// bulkTask is a two-item, two-step task with a callback.
func bulkTask(id string) *Task {
	task := newTask(id)
	task.Bulk = true
	task.Callback = &Callback{Endpoint: "https://pep.example.com/cb", State: "s1"}
	task.Workflow.Steps = append(task.Workflow.Steps, Step{Name: "owner", Required: 1, Approvers: []map[string]any{{"type": "user", "id": "owner"}}})
	task.Items = append(task.Items, Item{
		Index: 1, Resource: map[string]any{"type": "channel", "id": "eng"}, Action: map[string]any{"name": "can_post"},
		Status: StatusPending, Denial: map[string]any{"evaluation_id": "eval_2"},
	})
	return task
}

func testItemSteps(t *testing.T, s Store) {
	ctx := context.Background()
	if _, _, err := s.CreateTask(ctx, &NewTask{Task: bulkTask("arq_1")}, t0); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetTask(ctx, "arq_1")
	if !got.Bulk || got.Callback == nil || got.Callback.State != "s1" || got.Items[1].Denial["evaluation_id"] != "eval_2" {
		t.Fatalf("round trip lost phase 2 data: %+v", got)
	}
	// Item 0 moves to the owner step: the manager no longer sees the task
	// for it, but item 1 is still at the manager step.
	until := t0.Add(time.Hour)
	if _, err := s.UpdateTask(ctx, "arq_1", func(*Task) (*Change, error) {
		return &Change{ItemStep: map[int]int{0: 1}, NewDecisions: []Decision{{
			ItemIndex: 0, ApproverIss: "iss", ApproverSub: "manager", Decision: DecisionApprove, DecidedAt: t0, ApprovedUntil: &until,
		}}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetTask(ctx, "arq_1")
	if got.Items[0].CurrentStep != 1 || got.Items[1].CurrentStep != 0 || got.Decisions[0].ApprovedUntil == nil || !got.Decisions[0].ApprovedUntil.Equal(until) {
		t.Fatalf("item step or decision lifetime not persisted: %+v", got)
	}
	for approver, want := range map[string]int{"manager": 1, "owner": 1, "nobody": 0} {
		if page, _, err := s.ListPending(ctx, approver, "", 10); err != nil || len(page) != want {
			t.Fatalf("%s lists %v (%v)", approver, ids(page), err)
		}
	}
	// Once item 1 is denied, only the owner has work left.
	if _, err := s.UpdateTask(ctx, "arq_1", func(*Task) (*Change, error) {
		return &Change{ItemStatus: map[int]string{1: StatusDenied}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if page, _, _ := s.ListPending(ctx, "manager", "", 10); len(page) != 0 {
		t.Fatalf("manager still lists %v", ids(page))
	}
}

func testBulkExpiry(t *testing.T, s Store) {
	ctx := context.Background()
	task := bulkTask("arq_1")
	task.Items[1].Status = StatusApproved
	if _, _, err := s.CreateTask(ctx, &NewTask{Task: task}, t0); err != nil {
		t.Fatal(err)
	}
	expired, err := s.ExpireDue(ctx, t0.Add(2*time.Hour), 10)
	if err != nil || len(expired) != 1 || expired[0].Status != StatusPartial {
		t.Fatalf("a bulk task with an approved item expires as partial: %v %v", expired, err)
	}
	got, _ := s.GetTask(ctx, "arq_1")
	if got.Status != StatusPartial || got.Items[0].Status != StatusExpired || got.Items[1].Status != StatusApproved {
		t.Fatalf("expired bulk task: %+v", got)
	}
	// The callback asked for every event, so partial is enqueued.
	d, err := s.ClaimCallbacks(ctx, t0.Add(2*time.Hour), time.Minute, 10)
	if err != nil || len(d) != 1 || d[0].Event != StatusPartial {
		t.Fatalf("callback for the expiry: %+v %v", d, err)
	}
}

func testCallbacks(t *testing.T, s Store) {
	ctx := context.Background()
	quiet := bulkTask("arq_quiet")
	quiet.Callback.Events = []string{StatusApproved}
	tasks := []*Task{bulkTask("arq_1"), quiet}
	for _, task := range tasks {
		if _, _, err := s.CreateTask(ctx, &NewTask{Task: task}, t0); err != nil {
			t.Fatal(err)
		}
	}
	// A pending task notifies nobody.
	if d, _ := s.ClaimCallbacks(ctx, t0, time.Minute, 10); len(d) != 0 {
		t.Fatalf("pending task enqueued %+v", d)
	}
	for _, task := range tasks {
		done := t0
		if _, err := s.UpdateTask(ctx, task.ID, func(*Task) (*Change, error) {
			return &Change{Status: StatusDenied, CompletedAt: &done, ItemStatus: map[int]string{0: StatusDenied, 1: StatusDenied}}, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Only arq_1 asked for denied.
	claimed, err := s.ClaimCallbacks(ctx, t0, time.Minute, 10)
	if err != nil || len(claimed) != 1 || claimed[0].TaskID != "arq_1" || claimed[0].Event != StatusDenied || claimed[0].Attempts != 1 {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	// Claimed: not claimable again until the lease lapses.
	if d, _ := s.ClaimCallbacks(ctx, t0.Add(30*time.Second), time.Minute, 10); len(d) != 0 {
		t.Fatalf("claimed twice within the lease: %+v", d)
	}
	if d, _ := s.ClaimCallbacks(ctx, t0.Add(2*time.Minute), time.Minute, 10); len(d) != 1 || d[0].Attempts != 2 {
		t.Fatalf("lapsed lease not reclaimed: %+v", d)
	}
	id := claimed[0].ID
	if err := s.RetryCallback(ctx, id, t0.Add(10*time.Minute), "503"); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.ClaimCallbacks(ctx, t0.Add(5*time.Minute), time.Minute, 10); len(d) != 0 {
		t.Fatalf("claimed before the retry time: %+v", d)
	}
	if d, _ := s.ClaimCallbacks(ctx, t0.Add(10*time.Minute), time.Minute, 10); len(d) != 1 {
		t.Fatalf("retry not claimable: %+v", d)
	}
	if err := s.MarkDelivered(ctx, id, t0.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.ClaimCallbacks(ctx, t0.Add(time.Hour), time.Minute, 10); len(d) != 0 {
		t.Fatalf("delivered notification claimed again: %+v", d)
	}
}

func testPurge(t *testing.T, s Store) {
	ctx := context.Background()
	done := t0
	terminal := func(id string, approvals ...*Approval) {
		task := newTask(id)
		task.Status, task.Items[0].Status, task.CompletedAt = StatusApproved, StatusApproved, &done
		idem := Idempotency{Requester: "r", Key: id, BodyHash: []byte("h"), RetainUntil: task.ExpiresAt}
		if _, _, err := s.CreateTask(ctx, &NewTask{Task: task, Approvals: approvals, Idempotency: idem, JTIs: []JTI{{ID: id, Expires: t0}}}, t0); err != nil {
			t.Fatal(err)
		}
	}
	short := newApproval("apr_short", "arq_short")
	short.ApprovedUntil = t0.Add(2 * time.Hour)
	long := newApproval("apr_long", "arq_long")
	long.ApprovedUntil = t0.Add(48 * time.Hour)
	terminal("arq_short", short)
	terminal("arq_long", long)
	if _, _, err := s.CreateTask(ctx, &NewTask{Task: newTask("arq_pending")}, t0); err != nil {
		t.Fatal(err)
	}
	later := t0.Add(24 * time.Hour)
	// Two expired keys and identifiers: the most of any one kind.
	n, err := s.Purge(ctx, PurgeCutoffs{Tasks: later, Approvals: later, Now: later}, 10)
	if err != nil || n != 2 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if _, err := s.GetTask(ctx, "arq_short"); !errors.Is(err, ErrNotFound) {
		t.Fatal("an expired task whose approval lapsed survived")
	}
	if _, err := s.GetApproval(ctx, "apr_short"); !errors.Is(err, ErrNotFound) {
		t.Fatal("its approval survived")
	}
	// A task whose approval is still in force, and a pending task, stay.
	for _, id := range []string{"arq_long", "arq_pending"} {
		if _, err := s.GetTask(ctx, id); err != nil {
			t.Fatalf("%s purged: %v", id, err)
		}
	}
	// Its idempotency key and token identifier are gone: the key may be
	// reused and the token is no longer remembered.
	reuse := newTask("arq_reuse")
	if _, existed, err := s.CreateTask(ctx, &NewTask{
		Task: reuse, Idempotency: Idempotency{Requester: "r", Key: "arq_short", BodyHash: []byte("other"), RetainUntil: later.Add(time.Hour)},
		JTIs: []JTI{{ID: "arq_short", Expires: later.Add(time.Hour)}},
	}, later); err != nil || existed {
		t.Fatalf("purged key or identifier still held: %v %v", existed, err)
	}
}

func testUpdate(t *testing.T, s Store) {
	ctx := context.Background()
	if _, _, err := s.CreateTask(ctx, &NewTask{Task: newTask("arq_1")}, t0); err != nil {
		t.Fatal(err)
	}
	done := t0.Add(time.Minute)
	decision := Decision{ItemIndex: 0, Step: 0, ApproverIss: "iss", ApproverSub: "manager", Decision: DecisionApprove, DecidedAt: done}
	got, err := s.UpdateTask(ctx, "arq_1", func(task *Task) (*Change, error) {
		if task.Status != StatusPending {
			t.Fatalf("callback saw %s", task.Status)
		}
		return &Change{
			Status:       StatusApproved,
			CompletedAt:  &done,
			ItemStatus:   map[int]string{0: StatusApproved},
			ItemApproval: map[int]string{0: "apr_1"},
			NewDecisions: []Decision{decision},
			NewApprovals: []*Approval{newApproval("apr_1", "arq_1")},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusApproved || got.Items[0].ApprovalID != "apr_1" || len(got.Decisions) != 1 || got.Version != 1 {
		t.Fatalf("update result: %+v", got)
	}
	reloaded, _ := s.GetTask(ctx, "arq_1")
	if reloaded.Status != StatusApproved || reloaded.Items[0].Status != StatusApproved || len(reloaded.Decisions) != 1 || reloaded.CompletedAt == nil {
		t.Fatalf("update not persisted: %+v", reloaded)
	}
	if _, err := s.GetApproval(ctx, "apr_1"); err != nil {
		t.Fatalf("approval not persisted: %v", err)
	}
	// The same approver deciding the same step again conflicts.
	if _, err := s.UpdateTask(ctx, "arq_1", func(*Task) (*Change, error) {
		return &Change{NewDecisions: []Decision{decision}}, nil
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
	// An error from the callback persists nothing.
	boom := errors.New("boom")
	if _, err := s.UpdateTask(ctx, "arq_1", func(*Task) (*Change, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("expected the callback error, got %v", err)
	}
}

func testListPending(t *testing.T, s Store) {
	ctx := context.Background()
	for _, id := range []string{"arq_1", "arq_2", "arq_3"} {
		if _, _, err := s.CreateTask(ctx, &NewTask{Task: newTask(id)}, t0); err != nil {
			t.Fatal(err)
		}
	}
	other := newTask("arq_4")
	other.Workflow.Steps[0].Approvers = []map[string]any{{"type": "user", "id": "someone-else"}}
	if _, _, err := s.CreateTask(ctx, &NewTask{Task: other}, t0); err != nil {
		t.Fatal(err)
	}
	page, next, err := s.ListPending(ctx, "manager", "", 2)
	if err != nil || len(page) != 2 || page[0].ID != "arq_1" || next != "arq_2" {
		t.Fatalf("first page: %v next=%q err=%v", ids(page), next, err)
	}
	page, next, err = s.ListPending(ctx, "manager", next, 2)
	if err != nil || len(page) != 1 || page[0].ID != "arq_3" || next != "" {
		t.Fatalf("second page: %v next=%q err=%v", ids(page), next, err)
	}
}

func ids(ts []*Task) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.ID
	}
	return out
}

func testApprovals(t *testing.T, s Store) {
	ctx := context.Background()
	if _, _, err := s.CreateTask(ctx, &NewTask{Task: newTask("arq_1"), Approvals: []*Approval{newApproval("apr_1", "arq_1")}}, t0); err != nil {
		t.Fatal(err)
	}
	a, err := s.GetApproval(ctx, "apr_1")
	if err != nil || a.Context["project"] != "renewal" || a.BindingContextMembers[0] != "project" || a.RevokedAt != nil {
		t.Fatalf("approval: %+v %v", a, err)
	}
	r, err := s.RevokeApproval(ctx, "apr_1", "iss|manager", "left the team", t0.Add(time.Hour))
	if err != nil || r.RevokedAt == nil || r.RevokeReason != "left the team" {
		t.Fatalf("revoke: %+v %v", r, err)
	}
	if _, err := s.RevokeApproval(ctx, "apr_1", "x", "y", t0); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
	if _, err := s.RevokeApproval(ctx, "apr_missing", "x", "y", t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func testExpire(t *testing.T, s Store) {
	ctx := context.Background()
	soon := newTask("arq_soon")
	soon.ExpiresAt = t0.Add(time.Minute)
	later := newTask("arq_later")
	later.ExpiresAt = t0.Add(time.Hour)
	for _, task := range []*Task{soon, later} {
		if _, _, err := s.CreateTask(ctx, &NewTask{Task: task}, t0); err != nil {
			t.Fatal(err)
		}
	}
	expired, err := s.ExpireDue(ctx, t0.Add(2*time.Minute), 10)
	if err != nil || len(expired) != 1 || expired[0].ID != "arq_soon" || expired[0].Status != StatusExpired {
		t.Fatalf("expire: %v %v", ids(expired), err)
	}
	got, _ := s.GetTask(ctx, "arq_soon")
	if got.Status != StatusExpired || got.Items[0].Status != StatusExpired || got.CompletedAt == nil {
		t.Fatalf("expired task: %+v", got)
	}
	// Idempotent.
	if again, _ := s.ExpireDue(ctx, t0.Add(2*time.Minute), 10); len(again) != 0 {
		t.Fatalf("second sweep expired %v", again)
	}
}

// TestPostgresConcurrentMigrations starts several stores on one empty schema
// at once, as replicas starting together do: the advisory lock must let
// exactly one apply each migration.
func TestPostgresConcurrentMigrations(t *testing.T) {
	dsn := os.Getenv(testDSNEnv)
	if dsn == "" {
		t.Skipf("%s not set", testDSNEnv)
	}
	schema := fmt.Sprintf("ars_migrate_%d", os.Getpid())
	ctx := context.Background()
	var wg sync.WaitGroup
	stores := make([]*Postgres, 5)
	errs := make([]error, 5)
	for i := range stores {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stores[i], errs[i] = OpenPostgres(ctx, dsn, schema, 2)
		}(i)
	}
	wg.Wait()
	t.Cleanup(func() {
		for _, s := range stores {
			if s != nil {
				s.Close()
			}
		}
	})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("replica %d: %v", i, err)
		}
	}
	defer func() { _, _ = stores[0].pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	var applied int
	if err := stores[0].pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 2 {
		t.Fatalf("expected two recorded migrations, got %d", applied)
	}
}

// TestPostgresConcurrency checks the cross-replica guarantees with several
// connections: one winner for an idempotency key, one vote per approver.
func TestPostgresConcurrency(t *testing.T) {
	dsn := os.Getenv(testDSNEnv)
	if dsn == "" {
		t.Skipf("%s not set", testDSNEnv)
	}
	s := openTestPostgres(t, dsn)
	ctx := context.Background()

	idem := Idempotency{Requester: "iss|agent", Key: "race", BodyHash: []byte("h"), RetainUntil: t0.Add(time.Hour)}
	var wg sync.WaitGroup
	results := make([]string, 8)
	errs := make([]error, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			task, _, err := s.CreateTask(ctx, &NewTask{Task: newTask(fmt.Sprintf("arq_r%d", i)), Idempotency: idem}, t0)
			errs[i] = err
			if task != nil {
				results[i] = task.ID
			}
		}(i)
	}
	wg.Wait()
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("racing submit %d: %v", i, errs[i])
		}
		if results[i] != results[0] {
			t.Fatalf("racing submits produced different tasks: %v", results)
		}
	}

	if _, _, err := s.CreateTask(ctx, &NewTask{Task: newTask("arq_vote")}, t0); err != nil {
		t.Fatal(err)
	}
	var ok, conflicts int
	var mu sync.Mutex
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.UpdateTask(ctx, "arq_vote", func(task *Task) (*Change, error) {
				if task.Status != StatusPending {
					return nil, ErrConflict
				}
				done := t0
				return &Change{
					Status:       StatusApproved,
					CompletedAt:  &done,
					NewDecisions: []Decision{{ApproverIss: "iss", ApproverSub: "manager", Decision: DecisionApprove, DecidedAt: t0}},
				}, nil
			})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				ok++
			} else if errors.Is(err, ErrConflict) {
				conflicts++
			} else {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok != 1 || conflicts != 7 {
		t.Fatalf("expected exactly one decision to win, got %d wins and %d conflicts", ok, conflicts)
	}
}
