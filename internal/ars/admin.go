package ars

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
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
	errUnknownItem  = errors.New("no such item")
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

// isCandidateFor reports whether an approver is a candidate at the step a
// pending item is at.
func isCandidateFor(t *store.Task, it *store.Item, id *authn.Identity) bool {
	if it.Status != store.StatusPending || it.CurrentStep >= len(t.Workflow.Steps) {
		return false
	}
	return slices.ContainsFunc(t.Workflow.Steps[it.CurrentStep].Approvers, func(a map[string]any) bool {
		return approverMatches(a, id.Iss, id.Sub)
	})
}

// candidateItems lists the pending items the approver can decide now.
func candidateItems(t *store.Task, id *authn.Identity) []int {
	var out []int
	for i := range t.Items {
		if isCandidateFor(t, &t.Items[i], id) {
			out = append(out, i)
		}
	}
	return out
}

// adminView is a task as the approval UI sees it: the handle plus what the
// approver needs to decide. Unlike the requester's view it includes each
// item's step and denial, the workflow, and the decisions so far.
func (s *Service) adminView(t *store.Task) map[string]any {
	v := s.taskHandle(t)
	items := make([]any, len(t.Items))
	for i, it := range t.Items {
		d := it.Denial
		if d == nil {
			d = t.Denial
		}
		item := map[string]any{
			"index": it.Index, "resource": it.Resource, "action": it.Action,
			"requested_access": it.RequestedAccess, "status": it.Status, "current_step": it.CurrentStep + 1,
			"denial": map[string]any{"template": d["template"], "reason": d["reason"], "evaluation_id": d["evaluation_id"]},
		}
		if it.ApprovalID != "" {
			item["approval_id"] = it.ApprovalID
		}
		items[i] = item
	}
	decisions := make([]any, len(t.Decisions))
	for i, d := range t.Decisions {
		dv := map[string]any{
			"item": d.ItemIndex, "step": d.Step + 1, "approver": map[string]any{"iss": d.ApproverIss, "sub": d.ApproverSub},
			"decision": d.Decision, "comment": d.Comment, "decided_at": d.DecidedAt.UTC().Format(time.RFC3339),
		}
		if d.ApprovedUntil != nil {
			dv["approved_until"] = d.ApprovedUntil.UTC().Format(time.RFC3339)
		}
		decisions[i] = dv
	}
	v["request"] = map[string]any{
		"subject":          t.Subject,
		"items":            items,
		"context":          t.Context,
		"requested_access": t.RequestedAccess,
		"client":           t.Client,
		"requester":        map[string]any{"iss": t.RequesterIss, "sub": t.RequesterSub, "client_id": t.RequesterClient},
		"created_at":       t.CreatedAt.UTC().Format(time.RFC3339),
	}
	v["denial"] = map[string]any{"template": t.Template, "reason": t.Denial["reason"], "evaluation_id": t.EvaluationID}
	v["workflow"] = t.Workflow
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
		if len(candidateItems(t, approver)) == 0 {
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
		Decision      string `json:"decision"`
		Comment       string `json:"comment"`
		ApprovedUntil string `json:"approved_until"`
		Items         *[]int `json:"items"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&body); err != nil {
		badRequest(w, "the body must be a JSON object; items must be an array of item indexes")
		return
	}
	if body.Decision != store.DecisionApprove && body.Decision != store.DecisionDeny {
		badRequest(w, `decision must be "approve" or "deny"`)
		return
	}
	if body.Items != nil && len(*body.Items) == 0 {
		badRequest(w, "items must list at least one item")
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
	var advanced []int
	updated, err := s.d.Store.UpdateTask(r.Context(), t.ID, func(cur *store.Task) (*store.Change, error) {
		if store.IsTerminal(cur.Status) {
			return nil, store.ErrConflict
		}
		targets, err := decisionTargets(cur, approver, body.Items)
		if err != nil {
			return nil, err
		}
		// Eligibility (self-approval, separation of duties, delegation) is
		// the approver rule's, checked per item against the task as it now
		// stands. One refusal rejects the whole decision.
		for _, idx := range targets {
			it := cur.Items[idx]
			step := cur.Workflow.Steps[it.CurrentStep]
			ok, err := s.allowed(r.Context(), s.d.Rules.Approver, map[string]any{
				"operation": "decide",
				"approver":  approverInput(approver),
				"task":      ruleTask(cur),
				"item":      map[string]any{"index": idx, "resource": it.Resource, "action": it.Action},
				"step":      map[string]any{"index": it.CurrentStep, "name": step.Name, "required": step.Required},
				"decision":  map[string]any{"decision": body.Decision, "comment": body.Comment},
			})
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, errForbidden
			}
		}
		var ch *store.Change
		ch, advanced = s.applyDecision(cur, targets, approver, body.Decision, body.Comment, override, now)
		return ch, nil
	})
	switch {
	case errors.Is(err, store.ErrConflict):
		writeProblem(w, http.StatusConflict, ProblemInvalidState, "Decision not accepted", "the task or item is complete, or this approver already decided it at this step")
		return
	case errors.Is(err, errUnknownItem):
		badRequest(w, "items names an item the task does not have")
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
	for _, idx := range advanced {
		sc := s.auditTask(updated, approver)
		sc["item"], sc["step"] = strconv.Itoa(idx), strconv.Itoa(updated.Items[idx].CurrentStep)
		s.d.Audit.Emit(r.Context(), "step_completed", sc)
	}
	if store.IsTerminal(updated.Status) {
		s.d.Audit.Emit(r.Context(), updated.Status, s.auditTask(updated, approver))
	}
	writeJSON(w, http.StatusOK, map[string]any{"task": s.adminView(updated)})
}

// decisionTargets resolves which items a decision applies to: the listed
// ones, each pending with the approver a candidate at its step, or else
// every item the approver can decide now. An approver who already decided
// a target at its step conflicts.
func decisionTargets(t *store.Task, approver *authn.Identity, listed *[]int) ([]int, error) {
	var targets []int
	if listed == nil {
		if targets = candidateItems(t, approver); len(targets) == 0 {
			return nil, errNotCandidate
		}
	} else {
		for _, idx := range *listed {
			if idx < 0 || idx >= len(t.Items) {
				return nil, errUnknownItem
			}
			if slices.Contains(targets, idx) {
				continue
			}
			it := &t.Items[idx]
			if it.Status != store.StatusPending {
				return nil, store.ErrConflict
			}
			if !isCandidateFor(t, it, approver) {
				return nil, errNotCandidate
			}
			targets = append(targets, idx)
		}
	}
	for _, idx := range targets {
		step := t.Items[idx].CurrentStep
		if slices.ContainsFunc(t.Decisions, func(d store.Decision) bool {
			return d.ItemIndex == idx && d.Step == step && d.ApproverIss == approver.Iss && d.ApproverSub == approver.Sub
		}) {
			return nil, store.ErrConflict
		}
	}
	return targets, nil
}

// applyDecision records a decision on each target item and moves it on:
// a deny denies the item; an approve that completes its step's quorum
// either moves it to the next step or, on the last step, approves it with
// the shortest lifetime any of its approvers gave. It returns the change
// and the items that moved to a next step.
func (s *Service) applyDecision(t *store.Task, targets []int, approver *authn.Identity, decision, comment string, override *time.Time, now time.Time) (*store.Change, []int) {
	ch := &store.Change{ItemStatus: map[int]string{}, ItemApproval: map[int]string{}, ItemStep: map[int]int{}}
	var advanced []int
	for _, idx := range targets {
		it := &t.Items[idx]
		step := it.CurrentStep
		ch.NewDecisions = append(ch.NewDecisions, store.Decision{
			ItemIndex: idx, Step: step, ApproverIss: approver.Iss, ApproverSub: approver.Sub,
			Decision: decision, Comment: comment, DecidedAt: now, ApprovedUntil: override,
		})
		if decision == store.DecisionDeny {
			it.Status, ch.ItemStatus[idx] = store.StatusDenied, store.StatusDenied
			continue
		}
		approvals := 1
		for _, d := range t.Decisions {
			if d.ItemIndex == idx && d.Step == step && d.Decision == store.DecisionApprove {
				approvals++
			}
		}
		if approvals < t.Workflow.Steps[step].Required {
			continue
		}
		if step+1 < len(t.Workflow.Steps) {
			it.CurrentStep, ch.ItemStep[idx] = step+1, step+1
			advanced = append(advanced, idx)
			continue
		}
		a := s.newApproval(t, idx, now, shortestOverride(t, idx, override))
		ch.NewApprovals = append(ch.NewApprovals, a)
		it.Status, ch.ItemStatus[idx] = store.StatusApproved, store.StatusApproved
		ch.ItemApproval[idx] = a.ID
	}
	ch.Status = store.Aggregate(t.Items)
	step := store.EarliestStep(t.Items)
	ch.CurrentStep = &step
	if store.IsTerminal(ch.Status) {
		ch.CompletedAt = &now
	}
	return ch, advanced
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
