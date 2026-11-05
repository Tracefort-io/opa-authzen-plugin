package ars

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
	"github.com/Tracefort-io/opa-authzen-plugin/internal/authn"
)

// The approver API is a plugin extension, not part of ARAP: the profile
// leaves out how approvers discover and act on pending requests. A
// separately deployed UI calls it with the approver's own token.

const (
	defaultListLimit = 50
	maxListLimit     = 200
)

var (
	errNotCandidate = errors.New("approver is not a candidate for the current step")
	errForbidden    = errors.New("approver rule denied the operation")
)

// adminRoutes are the approver API handlers keyed by ServeMux pattern.
func (s *Service) adminRoutes() map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"GET " + AdminPath + "/tasks":                  s.handleListTasks,
		"GET " + AdminPath + "/tasks/{id}":             s.handleGetTask,
		"POST " + AdminPath + "/tasks/{id}/decisions":  s.handleDecide,
		"POST " + AdminPath + "/approvals/{id}/revoke": s.handleRevoke,
	}
}

func approverInput(id *authn.Identity) map[string]any {
	return map[string]any{"type": "user", "id": id.Sub, "properties": map[string]any{"iss": id.Iss}, "claims": id.Claims}
}

// approverMatches reports whether an authenticated approver is one of a
// step's candidates: a `user` entity with the approver's `sub`, and, when
// the entity names one, the approver's issuer in `properties.iss`.
func approverMatches(candidate map[string]any, iss, sub string) bool {
	if candidate["type"] != "user" || candidate["id"] != sub {
		return false
	}
	if props, ok := candidate["properties"].(map[string]any); ok {
		if want, ok := props["iss"].(string); ok && want != iss {
			return false
		}
	}
	return true
}

func isCandidate(t *store.Task, id *authn.Identity) bool {
	if t.CurrentStep >= len(t.Workflow.Steps) {
		return false
	}
	for _, a := range t.Workflow.Steps[t.CurrentStep].Approvers {
		if approverMatches(a, id.Iss, id.Sub) {
			return true
		}
	}
	return false
}

// adminView is a task as the approval UI sees it: the handle plus what the
// approver needs to decide. Unlike the requester's view it includes the
// candidate approvers and the decisions so far.
func (s *Service) adminView(t *store.Task) map[string]any {
	v := s.taskHandle(t)
	item := map[string]any{}
	if len(t.Items) > 0 {
		item = map[string]any{"resource": t.Items[0].Resource, "action": t.Items[0].Action, "status": t.Items[0].Status}
		if t.Items[0].ApprovalID != "" {
			item["approval_id"] = t.Items[0].ApprovalID
		}
	}
	decisions := make([]any, len(t.Decisions))
	for i, d := range t.Decisions {
		decisions[i] = map[string]any{
			"step": d.Step + 1, "approver": map[string]any{"iss": d.ApproverIss, "sub": d.ApproverSub},
			"decision": d.Decision, "comment": d.Comment, "decided_at": d.DecidedAt.UTC().Format(time.RFC3339),
		}
	}
	v["request"] = map[string]any{
		"subject":          t.Subject,
		"resource":         item["resource"],
		"action":           item["action"],
		"context":          t.Context,
		"requested_access": t.RequestedAccess,
		"client":           t.Client,
		"requester":        map[string]any{"iss": t.RequesterIss, "sub": t.RequesterSub, "client_id": t.RequesterClient},
		"created_at":       t.CreatedAt.UTC().Format(time.RFC3339),
	}
	v["denial"] = map[string]any{"template": t.Template, "reason": t.Denial["reason"], "evaluation_id": t.EvaluationID}
	v["workflow"] = t.Workflow
	v["item"] = item
	v["decisions"] = decisions
	return v
}

// handleListTasks serves GET /access/v1/admin/tasks: pending tasks whose
// current step lists the approver and that the approver rule lets them see.
func (s *Service) handleListTasks(w http.ResponseWriter, r *http.Request) {
	approver, err := s.d.Approvers.Authenticate(r)
	if err != nil {
		unauthenticated(w)
		return
	}
	q := r.URL.Query()
	if st := q.Get("status"); st != "" && st != store.StatusPending {
		badRequest(w, "only status=pending is supported")
		return
	}
	limit := defaultListLimit
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n <= 0 {
			badRequest(w, "limit must be a positive integer")
			return
		}
		limit = min(n, maxListLimit)
	}
	tasks, next, err := s.d.Store.ListPending(r.Context(), approver.Sub, q.Get("cursor"), limit)
	if err != nil {
		s.d.Logger.Error("AuthZEN approver API: listing tasks: %v", err)
		internalError(w)
		return
	}
	out := []any{}
	for _, t := range tasks {
		if !isCandidate(t, approver) {
			continue
		}
		ok, err := s.allowed(r.Context(), s.d.Rules.Approver, map[string]any{"operation": "list", "approver": approverInput(approver), "task": ruleTask(t)})
		if err != nil {
			s.d.Logger.Error("AuthZEN approver API: approver rule: %v", err)
			internalError(w)
			return
		}
		if ok {
			out = append(out, s.adminView(t))
		}
	}
	body := map[string]any{"tasks": out}
	if next != "" {
		body["next_cursor"] = next
	}
	writeJSON(w, http.StatusOK, body)
}

// loadForApprover authenticates the approver, loads the task, and checks
// the approver rule for op. A task the approver may not see is unknown.
func (s *Service) loadForApprover(w http.ResponseWriter, r *http.Request, op string) (*store.Task, *authn.Identity, bool) {
	approver, err := s.d.Approvers.Authenticate(r)
	if err != nil {
		unauthenticated(w)
		return nil, nil, false
	}
	t, err := s.d.Store.GetTask(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		unknownTask(w)
		return nil, nil, false
	}
	if err != nil {
		s.d.Logger.Error("AuthZEN approver API: loading task: %v", err)
		internalError(w)
		return nil, nil, false
	}
	ok, err := s.allowed(r.Context(), s.d.Rules.Approver, map[string]any{"operation": op, "approver": approverInput(approver), "task": ruleTask(t)})
	if err != nil {
		s.d.Logger.Error("AuthZEN approver API: approver rule: %v", err)
		internalError(w)
		return nil, nil, false
	}
	if !ok {
		unknownTask(w)
		return nil, nil, false
	}
	return t, approver, true
}

// handleGetTask serves GET /access/v1/admin/tasks/{id}.
func (s *Service) handleGetTask(w http.ResponseWriter, r *http.Request) {
	t, _, ok := s.loadForApprover(w, r, "view")
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"task": s.adminView(t)})
}

// handleDecide serves POST /access/v1/admin/tasks/{id}/decisions.
func (s *Service) handleDecide(w http.ResponseWriter, r *http.Request) {
	t, approver, ok := s.loadForApprover(w, r, "view")
	if !ok {
		return
	}
	var body struct {
		Decision      string          `json:"decision"`
		Comment       string          `json:"comment"`
		ApprovedUntil string          `json:"approved_until"`
		Items         json.RawMessage `json:"items"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&body); err != nil {
		badRequest(w, "the body must be a JSON object")
		return
	}
	if body.Decision != store.DecisionApprove && body.Decision != store.DecisionDeny {
		badRequest(w, `decision must be "approve" or "deny"`)
		return
	}
	if len(body.Items) > 0 {
		badRequest(w, "items is not supported")
		return
	}
	var override *time.Time
	if body.ApprovedUntil != "" {
		u, err := time.Parse(time.RFC3339, body.ApprovedUntil)
		if err != nil {
			badRequest(w, "approved_until must be an RFC 3339 timestamp")
			return
		}
		override = &u
	}

	now := s.now()
	var approval *store.Approval
	updated, err := s.d.Store.UpdateTask(r.Context(), t.ID, func(cur *store.Task) (*store.Change, error) {
		if store.IsTerminal(cur.Status) {
			return nil, store.ErrConflict
		}
		if !isCandidate(cur, approver) {
			return nil, errNotCandidate
		}
		// Eligibility (self-approval, separation of duties, delegation) is
		// the approver rule's, checked against the task as it now stands.
		step := cur.Workflow.Steps[cur.CurrentStep]
		ok, err := s.allowed(r.Context(), s.d.Rules.Approver, map[string]any{
			"operation": "decide",
			"approver":  approverInput(approver),
			"task":      ruleTask(cur),
			"step":      map[string]any{"index": cur.CurrentStep, "name": step.Name, "required": step.Required},
			"decision":  map[string]any{"decision": body.Decision, "comment": body.Comment},
		})
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errForbidden
		}
		decision := store.Decision{
			ItemIndex: 0, Step: cur.CurrentStep, ApproverIss: approver.Iss, ApproverSub: approver.Sub,
			Decision: body.Decision, Comment: body.Comment, DecidedAt: now,
		}
		ch := &store.Change{NewDecisions: []store.Decision{decision}}
		if body.Decision == store.DecisionDeny {
			ch.Status, ch.CompletedAt, ch.ItemStatus = store.StatusDenied, &now, map[int]string{0: store.StatusDenied}
			return ch, nil
		}
		approvals := 1
		for _, d := range cur.Decisions {
			if d.Step == cur.CurrentStep && d.ItemIndex == 0 && d.Decision == store.DecisionApprove {
				approvals++
			}
		}
		if approvals >= step.Required {
			approval = s.newApproval(cur, 0, bindingMembers(cur), now, override)
			ch.Status, ch.CompletedAt = store.StatusApproved, &now
			ch.ItemStatus = map[int]string{0: store.StatusApproved}
			ch.ItemApproval = map[int]string{0: approval.ID}
			ch.NewApprovals = []*store.Approval{approval}
		}
		return ch, nil
	})
	switch {
	case errors.Is(err, store.ErrConflict):
		writeProblem(w, http.StatusConflict, ProblemInvalidState, "Decision not accepted", "the task is complete or this approver already decided this step")
		return
	case errors.Is(err, errNotCandidate), errors.Is(err, errForbidden):
		forbidden(w)
		return
	case err != nil:
		s.d.Logger.Error("AuthZEN approver API: recording decision: %v", err)
		internalError(w)
		return
	}
	attrs := s.auditTask(updated, approver)
	attrs["decision"], attrs["comment"] = body.Decision, body.Comment
	s.d.Audit.Emit(r.Context(), "decided", attrs)
	if store.IsTerminal(updated.Status) {
		s.d.Audit.Emit(r.Context(), updated.Status, s.auditTask(updated, approver))
	}
	writeJSON(w, http.StatusOK, map[string]any{"task": s.adminView(updated)})
}

// bindingMembers reads the authorization-relevant context member names the
// denial was bound with; JSON round trips may leave them as []any.
func bindingMembers(t *store.Task) []string {
	switch m := t.Denial["binding_context_members"].(type) {
	case []string:
		return m
	case []any:
		out := make([]string, 0, len(m))
		for _, v := range m {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return []string{}
}

// handleRevoke serves POST /access/v1/admin/approvals/{id}/revoke. The next
// re-evaluation presenting the approval is denied.
func (s *Service) handleRevoke(w http.ResponseWriter, r *http.Request) {
	approver, err := s.d.Approvers.Authenticate(r)
	if err != nil {
		unauthenticated(w)
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&body); err != nil {
			badRequest(w, "the body must be a JSON object")
			return
		}
	}
	notFound := func() {
		writeProblem(w, http.StatusNotFound, problemGeneric, "Unknown approval", "")
	}
	a, err := s.d.Store.GetApproval(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		notFound()
		return
	}
	if err != nil {
		s.d.Logger.Error("AuthZEN approver API: loading approval: %v", err)
		internalError(w)
		return
	}
	t, err := s.d.Store.GetTask(r.Context(), a.TaskID)
	if err != nil {
		s.d.Logger.Error("AuthZEN approver API: loading task: %v", err)
		internalError(w)
		return
	}
	ok, err := s.allowed(r.Context(), s.d.Rules.Approver, map[string]any{
		"operation": "revoke", "approver": approverInput(approver), "task": ruleTask(t),
		"approval": map[string]any{"id": a.ID, "approved_until": a.ApprovedUntil.UTC().Format(time.RFC3339)},
	})
	if err != nil {
		s.d.Logger.Error("AuthZEN approver API: approver rule: %v", err)
		internalError(w)
		return
	}
	if !ok {
		notFound()
		return
	}
	revoked, err := s.d.Store.RevokeApproval(r.Context(), a.ID, approver.Key(), body.Reason, s.now())
	switch {
	case errors.Is(err, store.ErrConflict):
		writeProblem(w, http.StatusConflict, problemGeneric, "Approval already revoked", "")
		return
	case err != nil:
		s.d.Logger.Error("AuthZEN approver API: revoking approval: %v", err)
		internalError(w)
		return
	}
	attrs := s.auditTask(t, approver)
	attrs["approval_id"], attrs["reason"] = revoked.ID, body.Reason
	s.d.Audit.Emit(r.Context(), "revoked", attrs)
	writeJSON(w, http.StatusOK, map[string]any{"approval": map[string]any{
		"id":             revoked.ID,
		"task_id":        revoked.TaskID,
		"approved_until": revoked.ApprovedUntil.UTC().Format(time.RFC3339),
		"revoked_at":     revoked.RevokedAt.UTC().Format(time.RFC3339),
		"reason":         revoked.RevokeReason,
	}})
}
