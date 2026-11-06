package ars

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// submitPending submits the standard request and returns its task id.
func (f *fixture) submitPending(t *testing.T, jti string) string {
	t.Helper()
	claims := bindingClaims()
	claims["jti"] = jti
	w := f.do(t, http.MethodPost, RequestsPath, f.callerToken(t, "agent-7"), f.submission(t, claims))
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	return decode(t, w)["task"].(map[string]any)["id"].(string)
}

// adminItem is item i of the task in an approver API response.
func adminItem(t *testing.T, w *httptest.ResponseRecorder, i int) map[string]any {
	t.Helper()
	items := decode(t, w)["task"].(map[string]any)["request"].(map[string]any)["items"].([]any)
	return items[i].(map[string]any)
}

func TestAdminListOnlyCandidates(t *testing.T) {
	f := newFixture(t)
	id := f.submitPending(t, "j1")
	w := f.do(t, http.MethodGet, AdminPath+"/tasks", f.approverToken(t, "manager"), nil)
	tasks := decode(t, w)["tasks"].([]any)
	if w.Code != http.StatusOK || len(tasks) != 1 || tasks[0].(map[string]any)["id"] != id {
		t.Fatalf("manager list: %d %s", w.Code, w.Body.String())
	}
	view := tasks[0].(map[string]any)
	if view["request"].(map[string]any)["requester"].(map[string]any)["sub"] != "agent-7" || view["denial"].(map[string]any)["template"] != "manager_approval" {
		t.Fatalf("admin view: %v", view)
	}
	if got := decode(t, f.do(t, http.MethodGet, AdminPath+"/tasks", f.approverToken(t, "nobody"), nil))["tasks"].([]any); len(got) != 0 {
		t.Fatalf("a non-candidate sees %v", got)
	}
	f.rules["ars_approver"] = func(map[string]any) any { return false }
	if got := decode(t, f.do(t, http.MethodGet, AdminPath+"/tasks", f.approverToken(t, "manager"), nil))["tasks"].([]any); len(got) != 0 {
		t.Fatalf("the approver rule must filter the list: %v", got)
	}
	if w := f.do(t, http.MethodGet, AdminPath+"/tasks", f.callerToken(t, "manager"), nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("a caller-audience token on the approver API: %d", w.Code)
	}
}

func TestAdminApproveCompletesTask(t *testing.T) {
	f := newFixture(t)
	id := f.submitPending(t, "j1")
	w := f.do(t, http.MethodPost, AdminPath+"/tasks/"+id+"/decisions", f.approverToken(t, "manager"),
		map[string]any{"decision": "approve", "comment": "ok for the renewal", "approved_until": now.Add(2 * time.Hour).Format(time.RFC3339)})
	if w.Code != http.StatusOK {
		t.Fatalf("decide: %d %s", w.Code, w.Body.String())
	}
	view := decode(t, w)["task"].(map[string]any)
	if view["status"] != "approved" || len(view["decisions"].([]any)) != 1 {
		t.Fatalf("decided task: %v", view)
	}
	// The requester's status poll now carries the result.
	body := decode(t, f.do(t, http.MethodGet, RequestsPath+"/"+id, f.callerToken(t, "agent-7"), nil))
	approval := body["result"].(map[string]any)["approval"].(map[string]any)
	if approval["approved_until"] != now.Add(2*time.Hour).Format(time.RFC3339) {
		t.Fatalf("override not applied: %v", approval)
	}
	a, err := f.store.GetApproval(context.Background(), approval["id"].(string))
	if err != nil || a.Resource["id"] != "q4-plan" || a.Context["project"] != "renewal" || len(a.BindingContextMembers) != 1 {
		t.Fatalf("approval: %+v %v", a, err)
	}
	if w := f.do(t, http.MethodPost, AdminPath+"/tasks/"+id+"/decisions", f.approverToken(t, "manager"), map[string]any{"decision": "deny"}); w.Code != http.StatusConflict {
		t.Fatalf("deciding a complete task: %d", w.Code)
	}
}

func TestAdminDeny(t *testing.T) {
	f := newFixture(t)
	id := f.submitPending(t, "j1")
	w := f.do(t, http.MethodPost, AdminPath+"/tasks/"+id+"/decisions", f.approverToken(t, "manager"), map[string]any{"decision": "deny"})
	if w.Code != http.StatusOK || decode(t, w)["task"].(map[string]any)["status"] != "denied" {
		t.Fatalf("deny: %d %s", w.Code, w.Body.String())
	}
	if body := decode(t, f.do(t, http.MethodGet, RequestsPath+"/"+id, f.callerToken(t, "agent-7"), nil)); body["result"] != nil {
		t.Fatalf("a denied task carries a result: %v", body)
	}
}

func TestAdminDecisionAuthorization(t *testing.T) {
	f := newFixture(t)
	id := f.submitPending(t, "j1")
	path := AdminPath + "/tasks/" + id + "/decisions"
	if w := f.do(t, http.MethodPost, path, f.approverToken(t, "nobody"), map[string]any{"decision": "approve"}); w.Code != http.StatusForbidden {
		t.Fatalf("non-candidate: %d", w.Code)
	}
	// Separation of duties, expressed in the approver rule.
	f.rules["ars_approver"] = func(in map[string]any) any {
		return in["operation"] != "decide" || in["approver"].(map[string]any)["id"] != "manager"
	}
	if w := f.do(t, http.MethodPost, path, f.approverToken(t, "manager"), map[string]any{"decision": "approve"}); w.Code != http.StatusForbidden {
		t.Fatalf("rule-denied decision: %d", w.Code)
	}
	if w := f.do(t, http.MethodPost, path, f.approverToken(t, "manager"), map[string]any{"decision": "maybe"}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad decision: %d", w.Code)
	}
	f.rules["ars_approver"] = func(map[string]any) any { return true }
	if w := f.do(t, http.MethodPost, path, f.approverToken(t, "manager"), map[string]any{"decision": "approve", "items": []any{5}}); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown item: %d", w.Code)
	}
	if w := f.do(t, http.MethodPost, path, f.approverToken(t, "manager"), map[string]any{"decision": "approve", "items": []any{}}); w.Code != http.StatusBadRequest {
		t.Fatalf("empty items: %d", w.Code)
	}
	if got, _ := f.store.GetTask(context.Background(), id); got.Status != "pending" || len(got.Decisions) != 0 {
		t.Fatalf("a rejected decision changed the task: %+v", got)
	}
}

func TestAdminQuorum(t *testing.T) {
	f := newFixture(t)
	f.rules["ars_workflow"] = func(map[string]any) any {
		return map[string]any{"steps": []any{map[string]any{
			"name": "two_owners", "required": 2,
			"approvers": []any{map[string]any{"type": "user", "id": "owner-a"}, map[string]any{"type": "user", "id": "owner-b"}},
		}}}
	}
	id := f.submitPending(t, "j1")
	path := AdminPath + "/tasks/" + id + "/decisions"
	w := f.do(t, http.MethodPost, path, f.approverToken(t, "owner-a"), map[string]any{"decision": "approve"})
	if w.Code != http.StatusOK || decode(t, w)["task"].(map[string]any)["status"] != "pending" {
		t.Fatalf("first approval: %d %s", w.Code, w.Body.String())
	}
	if w := f.do(t, http.MethodPost, path, f.approverToken(t, "owner-a"), map[string]any{"decision": "approve"}); w.Code != http.StatusConflict {
		t.Fatalf("the same approver twice: %d", w.Code)
	}
	w = f.do(t, http.MethodPost, path, f.approverToken(t, "owner-b"), map[string]any{"decision": "approve"})
	if w.Code != http.StatusOK || decode(t, w)["task"].(map[string]any)["status"] != "approved" {
		t.Fatalf("quorum reached: %d %s", w.Code, w.Body.String())
	}
}

func TestAdminRevoke(t *testing.T) {
	f := newFixture(t)
	id := f.submitPending(t, "j1")
	w := f.do(t, http.MethodPost, AdminPath+"/tasks/"+id+"/decisions", f.approverToken(t, "manager"), map[string]any{"decision": "approve"})
	approvalID := adminItem(t, w, 0)["approval_id"].(string)
	path := AdminPath + "/approvals/" + approvalID + "/revoke"

	f.rules["ars_approver"] = func(in map[string]any) any { return in["operation"] != "revoke" }
	if w := f.do(t, http.MethodPost, path, f.approverToken(t, "manager"), nil); w.Code != http.StatusNotFound {
		t.Fatalf("rule-denied revoke: %d", w.Code)
	}
	f.rules["ars_approver"] = func(map[string]any) any { return true }
	w = f.do(t, http.MethodPost, path, f.approverToken(t, "manager"), map[string]any{"reason": "left the project"})
	if w.Code != http.StatusOK || decode(t, w)["approval"].(map[string]any)["reason"] != "left the project" {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if a, _ := f.store.GetApproval(context.Background(), approvalID); a.RevokedAt == nil || a.RevokedBy != idpIssuer+"|manager" {
		t.Fatalf("revocation not stored: %+v", a)
	}
	if w := f.do(t, http.MethodPost, path, f.approverToken(t, "manager"), nil); w.Code != http.StatusConflict {
		t.Fatalf("second revoke: %d", w.Code)
	}
	if w := f.do(t, http.MethodPost, AdminPath+"/approvals/apr_missing/revoke", f.approverToken(t, "manager"), nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown approval: %d", w.Code)
	}
}

func TestApproverMatchesIssuer(t *testing.T) {
	c := map[string]any{"type": "user", "id": "manager", "properties": map[string]any{"iss": "https://idp-a"}}
	if !approverMatches(c, "https://idp-a", "manager") || approverMatches(c, "https://idp-b", "manager") {
		t.Fatal("a candidate naming an issuer must match only that issuer")
	}
	if !approverMatches(map[string]any{"type": "user", "id": "manager"}, "https://any", "manager") {
		t.Fatal("a candidate without an issuer matches any trusted issuer")
	}
	if approverMatches(map[string]any{"type": "group", "id": "manager"}, "https://any", "manager") {
		t.Fatal("only user candidates match an approver")
	}
}

func TestSweeperExpiresDueTasks(t *testing.T) {
	f := newFixture(t)
	id := f.submitPending(t, "j1")
	f.svc.d.Now = func() time.Time { return now.Add(73 * time.Hour) }
	f.svc.sweep(context.Background())
	got, _ := f.store.GetTask(context.Background(), id)
	if got.Status != "expired" || got.Items[0].Status != "expired" {
		t.Fatalf("task not expired: %+v", got)
	}
	if f.audit.events[len(f.audit.events)-1] != "expired" {
		t.Fatalf("audit: %v", f.audit.events)
	}
	if w := f.do(t, http.MethodPost, AdminPath+"/tasks/"+id+"/decisions", f.approverToken(t, "manager"), map[string]any{"decision": "approve"}); w.Code != http.StatusConflict {
		t.Fatalf("approving an expired task: %d", w.Code)
	}
}
