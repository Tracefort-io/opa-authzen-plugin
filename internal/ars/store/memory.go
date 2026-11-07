package store

import (
	"bytes"
	"context"
	"maps"
	"slices"
	"sort"
	"sync"
	"time"
)

// Memory is an in-process Store for tests. It implements the same contract
// as Postgres under a single mutex; it is not shared between processes.
type Memory struct {
	mu          sync.Mutex
	tasks       map[string]*Task
	approvals   map[string]*Approval
	idempotency map[string]Idempotency // requester + "\x00" + key
	idemTask    map[string]string      // same key -> task id
	jtis        map[string]time.Time
	outbox      []*memDelivery
	nextOutbox  int64
}

type memDelivery struct {
	Delivery
	next      time.Time
	claimed   time.Time
	delivered bool
	failed    bool
	lastErr   string
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		tasks:       map[string]*Task{},
		approvals:   map[string]*Approval{},
		idempotency: map[string]Idempotency{},
		idemTask:    map[string]string{},
		jtis:        map[string]time.Time{},
	}
}

func cloneTask(t *Task) *Task {
	c := *t
	c.Items = slices.Clone(t.Items)
	c.Decisions = slices.Clone(t.Decisions)
	c.Workflow.Steps = slices.Clone(t.Workflow.Steps)
	if t.Callback != nil {
		cb := *t.Callback
		cb.Events = slices.Clone(t.Callback.Events)
		c.Callback = &cb
	}
	return &c
}

func cloneApproval(a *Approval) *Approval {
	c := *a
	c.BindingContextMembers = slices.Clone(a.BindingContextMembers)
	return &c
}

// CreateTask implements Store.
func (m *Memory) CreateTask(_ context.Context, n *NewTask, now time.Time) (*Task, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idemKey := n.Idempotency.Requester + "\x00" + n.Idempotency.Key
	if n.Idempotency.Key != "" {
		if prev, ok := m.idempotency[idemKey]; ok && prev.RetainUntil.After(now) {
			if !bytes.Equal(prev.BodyHash, n.Idempotency.BodyHash) {
				return nil, false, ErrDuplicateRequest
			}
			if t, ok := m.tasks[m.idemTask[idemKey]]; ok {
				return cloneTask(t), true, nil
			}
		}
	}
	seen := map[string]bool{}
	for _, j := range n.JTIs {
		if _, dup := m.jtis[j.ID]; dup || seen[j.ID] {
			return nil, false, ErrReplay
		}
		seen[j.ID] = true
	}
	for _, j := range n.JTIs {
		m.jtis[j.ID] = j.Expires
	}
	t := cloneTask(n.Task)
	m.tasks[t.ID] = t
	for _, a := range n.Approvals {
		m.approvals[a.ID] = cloneApproval(a)
	}
	if n.Idempotency.Key != "" {
		m.idempotency[idemKey] = n.Idempotency
		m.idemTask[idemKey] = t.ID
	}
	m.enqueue(t, now)
	return cloneTask(t), false, nil
}

// enqueue adds the callback notification of a task that has just become
// terminal, if its callback asked for that status.
func (m *Memory) enqueue(t *Task, now time.Time) {
	if !t.Callback.Wants(t.Status) {
		return
	}
	m.nextOutbox++
	m.outbox = append(m.outbox, &memDelivery{Delivery: Delivery{ID: m.nextOutbox, TaskID: t.ID, Event: t.Status}, next: now})
}

// GetTask implements Store.
func (m *Memory) GetTask(_ context.Context, id string) (*Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneTask(t), nil
}

// UpdateTask implements Store.
func (m *Memory) UpdateTask(_ context.Context, id string, fn func(*Task) (*Change, error)) (*Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, ok := m.tasks[id]
	if !ok {
		return nil, ErrNotFound
	}
	t := cloneTask(stored)
	ch, err := fn(cloneTask(t))
	if err != nil {
		return nil, err
	}
	if ch == nil {
		return t, nil
	}
	for _, d := range ch.NewDecisions {
		for _, prev := range t.Decisions {
			if prev.ItemIndex == d.ItemIndex && prev.Step == d.Step && prev.ApproverIss == d.ApproverIss && prev.ApproverSub == d.ApproverSub {
				return nil, ErrConflict
			}
		}
	}
	wasPending := t.Status == StatusPending
	applyChange(t, ch)
	m.tasks[id] = t
	for _, a := range ch.NewApprovals {
		m.approvals[a.ID] = cloneApproval(a)
	}
	if wasPending && IsTerminal(t.Status) {
		var at time.Time
		if t.CompletedAt != nil {
			at = *t.CompletedAt
		}
		m.enqueue(t, at)
	}
	return cloneTask(t), nil
}

// applyChange applies ch to t in memory. Shared with the Postgres store,
// which applies the same change to its returned copy.
func applyChange(t *Task, ch *Change) {
	if ch.Status != "" {
		t.Status = ch.Status
	}
	if ch.CurrentStep != nil {
		t.CurrentStep = *ch.CurrentStep
	}
	if ch.CompletedAt != nil {
		c := *ch.CompletedAt
		t.CompletedAt = &c
	}
	for i := range t.Items {
		if s, ok := ch.ItemStatus[t.Items[i].Index]; ok {
			t.Items[i].Status = s
		}
		if a, ok := ch.ItemApproval[t.Items[i].Index]; ok {
			t.Items[i].ApprovalID = a
		}
		if s, ok := ch.ItemStep[t.Items[i].Index]; ok {
			t.Items[i].CurrentStep = s
		}
	}
	t.Decisions = append(t.Decisions, ch.NewDecisions...)
	t.Version++
}

// expireChange is the change that expires a task's pending items.
func expireChange(t *Task, now time.Time) *Change {
	items := slices.Clone(t.Items)
	status := map[int]string{}
	for i := range items {
		if items[i].Status == StatusPending {
			items[i].Status = StatusExpired
			status[items[i].Index] = StatusExpired
		}
	}
	at := now
	return &Change{Status: Aggregate(items), CompletedAt: &at, ItemStatus: status}
}

// ListPending implements Store.
func (m *Memory) ListPending(_ context.Context, approverID, after string, limit int) ([]*Task, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []string
	for id, t := range m.tasks {
		if t.Status == StatusPending && id > after && pendingStepLists(t, approverID) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	next := ""
	if limit > 0 && len(ids) > limit {
		ids = ids[:limit]
		next = ids[len(ids)-1]
	}
	out := make([]*Task, len(ids))
	for i, id := range ids {
		out[i] = cloneTask(m.tasks[id])
	}
	return out, next, nil
}

func pendingStepLists(t *Task, approverID string) bool {
	for _, it := range t.Items {
		if it.Status != StatusPending || it.CurrentStep >= len(t.Workflow.Steps) {
			continue
		}
		for _, a := range t.Workflow.Steps[it.CurrentStep].Approvers {
			if a["type"] == "user" && a["id"] == approverID {
				return true
			}
		}
	}
	return false
}

// GetApproval implements Store.
func (m *Memory) GetApproval(_ context.Context, id string) (*Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.approvals[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneApproval(a), nil
}

// RevokeApproval implements Store.
func (m *Memory) RevokeApproval(_ context.Context, id, by, reason string, now time.Time) (*Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.approvals[id]
	if !ok {
		return nil, ErrNotFound
	}
	if a.RevokedAt != nil {
		return nil, ErrConflict
	}
	at := now
	a.RevokedAt, a.RevokedBy, a.RevokeReason = &at, by, reason
	return cloneApproval(a), nil
}

// ExpireDue implements Store.
func (m *Memory) ExpireDue(_ context.Context, now time.Time, limit int) ([]*Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []string
	for id, t := range m.tasks {
		if t.Status == StatusPending && !t.ExpiresAt.After(now) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if limit > 0 && len(ids) > limit {
		ids = ids[:limit]
	}
	out := make([]*Task, 0, len(ids))
	for _, id := range ids {
		t := m.tasks[id]
		applyChange(t, expireChange(t, now))
		m.enqueue(t, now)
		out = append(out, cloneTask(t))
	}
	return out, nil
}

// ClaimCallbacks implements Store.
func (m *Memory) ClaimCallbacks(_ context.Context, now time.Time, lease time.Duration, limit int) ([]Delivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Delivery
	for _, d := range m.outbox {
		if len(out) == limit {
			break
		}
		if d.delivered || d.failed || d.next.After(now) || d.claimed.After(now) {
			continue
		}
		d.Attempts++
		d.claimed = now.Add(lease)
		out = append(out, d.Delivery)
	}
	return out, nil
}

func (m *Memory) delivery(id int64) (*memDelivery, error) {
	for _, d := range m.outbox {
		if d.ID == id {
			return d, nil
		}
	}
	return nil, ErrNotFound
}

// MarkDelivered implements Store.
func (m *Memory) MarkDelivered(_ context.Context, id int64, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.delivery(id)
	if err == nil {
		d.delivered = true
	}
	return err
}

// RetryCallback implements Store.
func (m *Memory) RetryCallback(_ context.Context, id int64, next time.Time, lastErr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.delivery(id)
	if err == nil {
		d.next, d.claimed, d.lastErr = next, time.Time{}, lastErr
	}
	return err
}

// FailCallback implements Store.
func (m *Memory) FailCallback(_ context.Context, id int64, _ time.Time, lastErr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.delivery(id)
	if err == nil {
		d.failed, d.lastErr = true, lastErr
	}
	return err
}

// RememberJTI implements Store.
func (m *Memory) RememberJTI(_ context.Context, id string, expires time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, seen := m.jtis[id]; seen {
		return false, nil
	}
	m.jtis[id] = expires
	return true, nil
}

// Backlog implements Store.
func (m *Memory) Backlog(context.Context) (int64, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var pending, undelivered int64
	for _, t := range m.tasks {
		if t.Status == StatusPending {
			pending++
		}
	}
	for _, d := range m.outbox {
		if !d.delivered && !d.failed {
			undelivered++
		}
	}
	return pending, undelivered, nil
}

// Purge implements Store.
func (m *Memory) Purge(_ context.Context, c PurgeCutoffs, limit int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []string
	for id, t := range m.tasks {
		if IsTerminal(t.Status) && t.ExpiresAt.Before(c.Tasks) && !m.approvalInForce(id, c.Approvals) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if limit > 0 && len(ids) > limit {
		ids = ids[:limit]
	}
	for _, id := range ids {
		delete(m.tasks, id)
		maps.DeleteFunc(m.approvals, func(_ string, a *Approval) bool { return a.TaskID == id })
		m.outbox = slices.DeleteFunc(m.outbox, func(d *memDelivery) bool { return d.TaskID == id })
	}
	// Memory deletes every expired key and identifier at once; only tasks
	// are batched.
	keys := 0
	for k, idem := range m.idempotency {
		if idem.RetainUntil.Before(c.Now) {
			delete(m.idempotency, k)
			delete(m.idemTask, k)
			keys++
		}
	}
	jtis := len(m.jtis)
	maps.DeleteFunc(m.jtis, func(_ string, exp time.Time) bool { return exp.Before(c.Now) })
	return max(len(ids), keys, jtis-len(m.jtis)), nil
}

func (m *Memory) approvalInForce(taskID string, cutoff time.Time) bool {
	for _, a := range m.approvals {
		if a.TaskID == taskID && !a.ApprovedUntil.Before(cutoff) {
			return true
		}
	}
	return false
}

// Close implements Store.
func (m *Memory) Close() {}
