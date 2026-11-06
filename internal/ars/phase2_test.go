package ars

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
)

// twoSteps is a workflow of a manager step then an owner step.
func twoSteps(map[string]any) any {
	return map[string]any{"steps": []any{
		map[string]any{"name": "manager_approval", "approvers": []any{map[string]any{"type": "user", "id": "manager"}}},
		map[string]any{"name": "owner_approval", "disclose_approvers": true, "approvers": []any{map[string]any{"type": "user", "id": "owner"}}},
	}}
}

func (f *fixture) decide(t *testing.T, id, approver string, body map[string]any) map[string]any {
	t.Helper()
	w := f.do(t, http.MethodPost, AdminPath+"/tasks/"+id+"/decisions", f.approverToken(t, approver), body)
	if w.Code != http.StatusOK {
		t.Fatalf("%s decides %v: %d %s", approver, body, w.Code, w.Body.String())
	}
	return decode(t, w)["task"].(map[string]any)
}

func TestMultiStepApproval(t *testing.T) {
	f := newFixture(t)
	f.rules["ars_workflow"] = twoSteps
	id := f.submitPending(t, "j1")
	path := AdminPath + "/tasks/" + id + "/decisions"

	// The owner is not a candidate until the manager step completes.
	if w := f.do(t, http.MethodPost, path, f.approverToken(t, "owner"), map[string]any{"decision": "approve"}); w.Code != http.StatusForbidden {
		t.Fatalf("owner before their step: %d", w.Code)
	}
	if got := decode(t, f.do(t, http.MethodGet, AdminPath+"/tasks", f.approverToken(t, "owner"), nil))["tasks"].([]any); len(got) != 0 {
		t.Fatalf("owner lists a task not yet at their step: %v", got)
	}
	task := f.decide(t, id, "manager", map[string]any{"decision": "approve", "approved_until": now.Add(6 * time.Hour).Format(time.RFC3339)})
	if task["status"] != "pending" || task["progress"].(map[string]any)["step_name"] != "owner_approval" {
		t.Fatalf("after the manager step: %v", task)
	}
	if !slices.Contains(f.audit.events, "step_completed") {
		t.Fatalf("no step_completed record: %v", f.audit.events)
	}
	// The requester sees the second step, and who it awaits.
	handle := decode(t, f.do(t, http.MethodGet, RequestsPath+"/"+id, f.callerToken(t, "agent-7"), nil))["task"].(map[string]any)
	progress := handle["progress"].(map[string]any)
	if progress["current_step"] != float64(2) || progress["total_steps"] != float64(2) || progress["awaiting"].([]any)[0] != "owner" {
		t.Fatalf("progress: %v", progress)
	}
	// The manager's vote was for step 1; the manager is no candidate now.
	if w := f.do(t, http.MethodPost, path, f.approverToken(t, "manager"), map[string]any{"decision": "approve"}); w.Code != http.StatusForbidden {
		t.Fatalf("manager at the owner step: %d", w.Code)
	}
	// The owner gives a longer lifetime; the shorter one from step 1 wins.
	task = f.decide(t, id, "owner", map[string]any{"decision": "approve", "approved_until": now.Add(12 * time.Hour).Format(time.RFC3339)})
	if task["status"] != "approved" {
		t.Fatalf("after the owner step: %v", task)
	}
	body := decode(t, f.do(t, http.MethodGet, RequestsPath+"/"+id, f.callerToken(t, "agent-7"), nil))
	if got := body["result"].(map[string]any)["approval"].(map[string]any)["approved_until"]; got != now.Add(6*time.Hour).Format(time.RFC3339) {
		t.Fatalf("approved_until %v, want the shortest an approver gave", got)
	}
}

func TestMultiStepDenyAtLaterStep(t *testing.T) {
	f := newFixture(t)
	f.rules["ars_workflow"] = twoSteps
	id := f.submitPending(t, "j1")
	f.decide(t, id, "manager", map[string]any{"decision": "approve"})
	if task := f.decide(t, id, "owner", map[string]any{"decision": "deny"}); task["status"] != "denied" {
		t.Fatalf("a deny at step 2 denies: %v", task)
	}
}

// Separation of duties across steps is the approver rule's: it sees which
// steps an approver already decided.
func TestMultiStepSeparationOfDuties(t *testing.T) {
	f := newFixture(t)
	f.rules["ars_workflow"] = func(map[string]any) any {
		both := []any{map[string]any{"type": "user", "id": "alex"}, map[string]any{"type": "user", "id": "sam"}}
		return map[string]any{"steps": []any{
			map[string]any{"name": "first", "approvers": both},
			map[string]any{"name": "second", "approvers": both},
		}}
	}
	f.rules["ars_approver"] = func(in map[string]any) any {
		if in["operation"] != "decide" {
			return true
		}
		me := in["approver"].(map[string]any)["id"]
		step := in["step"].(map[string]any)["index"].(int)
		for _, d := range in["task"].(map[string]any)["decisions"].([]any) {
			dm := d.(map[string]any)
			if dm["approver"].(map[string]any)["sub"] == me && dm["step"].(int) < step {
				return false
			}
		}
		return true
	}
	id := f.submitPending(t, "j1")
	f.decide(t, id, "alex", map[string]any{"decision": "approve"})
	if w := f.do(t, http.MethodPost, AdminPath+"/tasks/"+id+"/decisions", f.approverToken(t, "alex"), map[string]any{"decision": "approve"}); w.Code != http.StatusForbidden {
		t.Fatalf("the same approver on both steps: %d", w.Code)
	}
	if task := f.decide(t, id, "sam", map[string]any{"decision": "approve"}); task["status"] != "approved" {
		t.Fatalf("a second approver completes it: %v", task)
	}
}

func TestPlanValidation(t *testing.T) {
	step := func(name string) any {
		return map[string]any{"name": name, "approvers": []any{map[string]any{"type": "user", "id": "m"}}}
	}
	cases := map[string]struct {
		plan  map[string]any
		items int
		ok    bool
	}{
		"two steps":              {map[string]any{"steps": []any{step("a"), step("b")}}, 1, true},
		"duplicate step names":   {map[string]any{"steps": []any{step("a"), step("a")}}, 1, false},
		"too many steps":         {map[string]any{"steps": []any{step("a"), step("b"), step("c")}}, 1, false},
		"auto for every item":    {map[string]any{"auto": []any{"approve", "deny"}}, 2, true},
		"auto array, steps rest": {map[string]any{"auto": []any{"approve", nil}, "steps": []any{step("a")}}, 2, true},
		"auto array, no steps":   {map[string]any{"auto": []any{"approve", nil}}, 2, false},
		"auto array too short":   {map[string]any{"auto": []any{"approve"}}, 2, false},
		"auto array bad value":   {map[string]any{"auto": []any{"maybe", "deny"}}, 2, false},
		"auto null":              {map[string]any{"auto": nil}, 1, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePlan(c.plan, c.items, 2); (err == nil) != c.ok {
				t.Fatalf("parsePlan: %v", err)
			}
		})
	}
}

// bulkItem is a requested item and its own binding_token claims.
func bulkItem(id, action, jti string) (map[string]any, map[string]any) {
	resource := map[string]any{"type": "document", "id": id}
	act := map[string]any{"name": action}
	claims := bindingClaims()
	claims["resource"], claims["action"], claims["jti"], claims["evaluation_id"] = resource, act, jti, "eval_"+jti
	return map[string]any{"resource": resource, "action": act}, claims
}

// bulkSubmission is a two-item submission, each item with its own denial,
// as a PEP builds it from a batch evaluation.
func (f *fixture) bulkSubmission(t *testing.T) map[string]any {
	body := f.submission(t, bindingClaims())
	delete(body, "resource")
	delete(body, "action")
	delete(body, "denial")
	var items []any
	for i, id := range []string{"q4-plan", "q3-plan"} {
		item, claims := bulkItem(id, "can_read", "jb"+strings.Repeat("x", i))
		item["denial"] = map[string]any{
			"expires_at": claims["denial_expires_at"], "evaluation_id": claims["evaluation_id"],
			"binding_token": signJWT(t, f.pdpKey, claims), "template": "doc_access",
		}
		items = append(items, item)
	}
	body["items"] = items
	return body
}

func TestBulkSubmissionAndDecisions(t *testing.T) {
	f := newFixture(t)
	w := f.do(t, http.MethodPost, RequestsPath, f.callerToken(t, "agent-7"), f.bulkSubmission(t))
	if w.Code != http.StatusAccepted {
		t.Fatalf("bulk submit: %d %s", w.Code, w.Body.String())
	}
	task := decode(t, w)["task"].(map[string]any)
	id := task["id"].(string)
	if items := task["items"].([]any); len(items) != 2 || items[1].(map[string]any)["resource"].(map[string]any)["id"] != "q3-plan" {
		t.Fatalf("handle items: %v", task["items"])
	}
	stored, _ := f.store.GetTask(context.Background(), id)
	if !stored.Bulk || stored.Items[1].Denial["evaluation_id"] != "eval_jbx" {
		t.Fatalf("per-item denial not stored: %+v", stored.Items)
	}

	// Approve item 0 only, then deny the rest: the task is partial.
	f.decide(t, id, "manager", map[string]any{"decision": "approve", "items": []any{0}})
	if w := f.do(t, http.MethodPost, AdminPath+"/tasks/"+id+"/decisions", f.approverToken(t, "manager"), map[string]any{"decision": "deny", "items": []any{0}}); w.Code != http.StatusConflict {
		t.Fatalf("deciding a completed item: %d", w.Code)
	}
	if task := f.decide(t, id, "manager", map[string]any{"decision": "deny"}); task["status"] != store.StatusPartial {
		t.Fatalf("mixed outcome: %v", task["status"])
	}

	body := decode(t, f.do(t, http.MethodGet, RequestsPath+"/"+id, f.callerToken(t, "agent-7"), nil))
	if body["result"] != nil {
		t.Fatalf("a bulk task carries a top-level result: %v", body["result"])
	}
	items := body["task"].(map[string]any)["items"].([]any)
	approved, denied := items[0].(map[string]any), items[1].(map[string]any)
	if approved["status"] != "approved" || denied["status"] != "denied" || denied["result"] != nil {
		t.Fatalf("items: %v", items)
	}
	approval := approved["result"].(map[string]any)["approval"].(map[string]any)
	a, err := f.store.GetApproval(context.Background(), approval["id"].(string))
	if err != nil || a.ItemIndex != 0 || a.Resource["id"] != "q4-plan" {
		t.Fatalf("item 0's approval: %+v %v", a, err)
	}
}

func TestBulkPerItemAuto(t *testing.T) {
	f := newFixture(t)
	f.rules["ars_workflow"] = func(in map[string]any) any {
		if !in["submission"].(map[string]any)["bulk"].(bool) {
			t.Error("the workflow rule is not told the submission is bulk")
		}
		plan := twoSteps(nil).(map[string]any)
		plan["auto"] = []any{"approve", nil}
		return plan
	}
	w := f.do(t, http.MethodPost, RequestsPath, f.callerToken(t, "agent-7"), f.bulkSubmission(t))
	body := decode(t, w)
	task := body["task"].(map[string]any)
	items := task["items"].([]any)
	if w.Code != http.StatusAccepted || task["status"] != "pending" || items[0].(map[string]any)["status"] != "approved" || items[0].(map[string]any)["result"] == nil {
		t.Fatalf("auto-approved item: %d %v", w.Code, body)
	}
	id := task["id"].(string)
	// The requester cancels: item 0 stays approved, so the task is partial.
	w = f.do(t, http.MethodPost, RequestsPath+"/"+id+"/cancel", f.callerToken(t, "agent-7"), nil)
	task = decode(t, w)["task"].(map[string]any)
	items = task["items"].([]any)
	if task["status"] != store.StatusPartial || items[0].(map[string]any)["status"] != "approved" || items[1].(map[string]any)["status"] != "cancelled" {
		t.Fatalf("cancelled bulk task: %v", task)
	}
	if items[0].(map[string]any)["result"] == nil {
		t.Fatal("an approved item lost its result on cancellation")
	}
}

func TestBulkSweeperPartial(t *testing.T) {
	f := newFixture(t)
	f.rules["ars_workflow"] = func(map[string]any) any {
		plan := twoSteps(nil).(map[string]any)
		plan["auto"] = []any{"deny", nil}
		return plan
	}
	id := decode(t, f.do(t, http.MethodPost, RequestsPath, f.callerToken(t, "agent-7"), f.bulkSubmission(t)))["task"].(map[string]any)["id"].(string)
	f.svc.d.Now = func() time.Time { return now.Add(73 * time.Hour) }
	f.svc.sweep(context.Background())
	got, _ := f.store.GetTask(context.Background(), id)
	if got.Status != store.StatusPartial || got.Items[1].Status != store.StatusExpired {
		t.Fatalf("expired bulk task: %+v", got)
	}
	if f.audit.events[len(f.audit.events)-1] != store.StatusPartial {
		t.Fatalf("audit: %v", f.audit.events)
	}
}

func TestBulkRejects(t *testing.T) {
	f := newFixture(t)
	f.svc.d.MaxItems = 2
	tok := f.callerToken(t, "agent-7")
	withBody := func(edit func(b map[string]any)) map[string]any {
		b := f.bulkSubmission(t)
		edit(b)
		return b
	}
	item := func(b map[string]any, i int) map[string]any { return b["items"].([]any)[i].(map[string]any) }
	cases := map[string]struct {
		body   map[string]any
		status int
		typ    string
	}{
		"items with resource": {withBody(func(b map[string]any) { b["resource"] = map[string]any{"type": "document", "id": "x"} }), 400, problemGeneric},
		"empty items":         {withBody(func(b map[string]any) { b["items"] = []any{} }), 400, problemGeneric},
		"too many items": {withBody(func(b map[string]any) {
			b["items"] = append(b["items"].([]any), item(b, 0))
		}), 400, problemGeneric},
		"item without denial, none at top": {withBody(func(b map[string]any) { delete(item(b, 1), "denial") }), 400, ProblemNotRequestable},
		// A single-item token cannot stand in for a bundle denial.
		"top-level denial for two items": {withBody(func(b map[string]any) {
			b["denial"] = item(b, 0)["denial"]
			delete(item(b, 0), "denial")
			delete(item(b, 1), "denial")
		}), 400, ProblemInvalidBinding},
		"one token on two items": {withBody(func(b map[string]any) {
			item(b, 1)["denial"] = item(b, 0)["denial"]
			item(b, 1)["resource"] = item(b, 0)["resource"]
		}), 400, ProblemInvalidBinding},
		"items reordered": {withBody(func(b map[string]any) {
			item(b, 0)["denial"], item(b, 1)["denial"] = item(b, 1)["denial"], item(b, 0)["denial"]
		}), 400, ProblemInvalidBinding},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			w := f.do(t, http.MethodPost, RequestsPath, tok, c.body)
			if w.Code != c.status || problemType(t, w) != c.typ {
				t.Fatalf("expected %d %s, got %d %s", c.status, c.typ, w.Code, w.Body.String())
			}
		})
	}
}

func TestPurgeKeepsLiveApprovals(t *testing.T) {
	f := newFixture(t)
	f.rules["ars_workflow"] = func(map[string]any) any {
		return map[string]any{"auto": "approve", "approved_until": now.Add(200 * time.Hour).Format(time.RFC3339)}
	}
	long := decode(t, f.do(t, http.MethodPost, RequestsPath, f.callerToken(t, "agent-7"), f.submission(t, bindingClaims())))["task"].(map[string]any)["id"].(string)
	f.rules["ars_workflow"] = func(map[string]any) any { return map[string]any{"auto": "deny"} }
	claims := bindingClaims()
	claims["jti"] = "j2"
	denied := decode(t, f.do(t, http.MethodPost, RequestsPath, f.callerToken(t, "agent-7"), f.submission(t, claims)))["task"].(map[string]any)["id"].(string)

	// Past task_ttl + idempotency_retention, before the approval lapses.
	f.svc.d.Now = func() time.Time { return now.Add(100 * time.Hour) }
	f.svc.purge(context.Background())
	if _, err := f.store.GetTask(context.Background(), denied); err == nil {
		t.Fatal("the denied task outlived its retention")
	}
	if _, err := f.store.GetTask(context.Background(), long); err != nil {
		t.Fatalf("a task with an approval in force was purged: %v", err)
	}
	f.svc.d.Now = func() time.Time { return now.Add(201 * time.Hour) }
	f.svc.purge(context.Background())
	if _, err := f.store.GetTask(context.Background(), long); err == nil {
		t.Fatal("the task outlived its approval")
	}
}
