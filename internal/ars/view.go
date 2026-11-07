package ars

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
)

// taskHandle renders the ARAP Task Handle a PEP sees, without results. A
// bulk task lists its items (Bulk Profile "Response Items and
// Aggregation").
func (s *Service) taskHandle(t *store.Task) map[string]any {
	h := map[string]any{
		"id":              t.ID,
		"status":          t.Status,
		"status_endpoint": s.statusEndpoint(t.ID),
		"expires_at":      t.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if t.Display != nil {
		h["display"] = t.Display
	}
	if p := progress(t); p != nil {
		h["progress"] = p
	}
	if t.Bulk {
		items := make([]any, len(t.Items))
		for i, it := range t.Items {
			items[i] = map[string]any{"resource": it.Resource, "action": it.Action, "status": it.Status}
		}
		h["items"] = items
	}
	links := map[string]any{"cancel": s.statusEndpoint(t.ID) + "/cancel"}
	if s.d.Links.Ticket != "" {
		links["ticket"] = strings.ReplaceAll(s.d.Links.Ticket, "{id}", t.ID)
	}
	if s.d.Links.Review != "" {
		links["review"] = strings.ReplaceAll(s.d.Links.Review, "{id}", t.ID)
	}
	h["links"] = links
	return h
}

// progress describes a pending task's earliest step: the step some pending
// item still waits at. Approver identities are disclosed only where the
// workflow allows it (ARAP "Privacy Considerations").
func progress(t *store.Task) map[string]any {
	if t.Status != store.StatusPending {
		return nil
	}
	step := store.EarliestStep(t.Items)
	if step >= len(t.Workflow.Steps) {
		return nil
	}
	st := t.Workflow.Steps[step]
	p := map[string]any{
		"current_step": step + 1,
		"total_steps":  len(t.Workflow.Steps),
		"step_name":    st.Name,
	}
	if st.DiscloseApprovers {
		awaiting := []string{}
		for _, a := range st.Approvers {
			if awaitingApprover(t, step, a) {
				id, _ := a["id"].(string)
				awaiting = append(awaiting, id)
			}
		}
		p["awaiting"] = awaiting
	}
	return p
}

// awaitingApprover reports whether a candidate of step has yet to decide
// some pending item at that step.
func awaitingApprover(t *store.Task, step int, candidate map[string]any) bool {
	for _, it := range t.Items {
		if it.Status == store.StatusPending && it.CurrentStep == step && !decided(t, it.Index, step, candidate) {
			return true
		}
	}
	return false
}

func decided(t *store.Task, item, step int, candidate map[string]any) bool {
	return slices.ContainsFunc(t.Decisions, func(d store.Decision) bool {
		return d.ItemIndex == item && d.Step == step && approverMatches(candidate, d.ApproverIss, d.ApproverSub)
	})
}

// render is the response body for a task: its handle and, per the task's
// shape, the completion results. A single-item approved task carries the
// top-level `result`; a bulk task carries a `result` on each approved item
// and no top-level one, so no PEP can take it for approval of every item.
func (s *Service) render(ctx context.Context, t *store.Task) (map[string]any, error) {
	h := s.taskHandle(t)
	body := map[string]any{"task": h}
	if !t.Bulk {
		if t.Status == store.StatusApproved && len(t.Items) > 0 && t.Items[0].ApprovalID != "" {
			res, err := s.itemResult(ctx, t.Items[0].ApprovalID)
			if err != nil {
				return nil, err
			}
			body["result"] = res
		}
		return body, nil
	}
	items, _ := h["items"].([]any)
	for i, it := range t.Items {
		if it.Status != store.StatusApproved || it.ApprovalID == "" {
			continue
		}
		res, err := s.itemResult(ctx, it.ApprovalID)
		if err != nil {
			return nil, err
		}
		items[i].(map[string]any)["result"] = res
	}
	return body, nil
}

// itemResult renders the completion result of an approved item (ARAP
// "Approval Result"): re-evaluate, with the approval and a signed
// approval.state other PDPs trusting this one can verify.
func (s *Service) itemResult(ctx context.Context, approvalID string) (map[string]any, error) {
	a, err := s.d.Store.GetApproval(ctx, approvalID)
	if err != nil {
		return nil, err
	}
	state, err := s.d.Crypto.SignApprovalState(s.approvalClaims(a))
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"mode": "reevaluate",
		"approval": map[string]any{
			"id":             a.ID,
			"approved_at":    a.ApprovedAt.UTC().Format(time.RFC3339),
			"approved_until": a.ApprovedUntil.UTC().Format(time.RFC3339),
			"state":          state,
		},
	}, nil
}

// approvalClaims are the approval.state claims, in the form the plugin's
// signed-approval verification reads. With ApprovalStateTTL, `exp` is the
// earlier of approved_until and now plus the TTL: a PDP verifying the
// signature cannot see revocation, and the TTL bounds how long it honours
// a revoked approval. A PEP refreshes the state by reading the task.
func (s *Service) approvalClaims(a *store.Approval) map[string]any {
	exp := a.ApprovedUntil
	if ttl := s.d.ApprovalStateTTL; ttl > 0 && s.now().Add(ttl).Before(exp) {
		exp = s.now().Add(ttl)
	}
	// ARAP: `aud` identifies the verifying PDPs, this one and any peer.
	var aud any = s.d.BaseURL
	if len(s.d.ApprovalStateAudiences) > 0 {
		aud = append([]string{s.d.BaseURL}, s.d.ApprovalStateAudiences...)
	}
	return map[string]any{
		"iss":                     s.d.BaseURL,
		"aud":                     aud,
		"exp":                     exp.Unix(),
		"approval_id":             a.ID,
		"task_id":                 a.TaskID,
		"approved_at":             a.ApprovedAt.UTC().Format(time.RFC3339),
		"approved_until":          a.ApprovedUntil.UTC().Format(time.RFC3339),
		"subject":                 a.Subject,
		"resource":                a.Resource,
		"action":                  a.Action,
		"binding_context_members": a.BindingContextMembers,
		"context":                 a.Context,
	}
}

// ruleClient is a stored `client` as the rules see it. A stored actor was
// verified at submission; `source` cannot be verified and stays out.
func ruleClient(c map[string]any) map[string]any {
	if c == nil {
		return nil
	}
	out := map[string]any{}
	for k, v := range c {
		if k != "source" {
			out[k] = v
		}
	}
	if _, ok := c["actor"]; ok {
		out["actor_verified"] = true
	}
	return out
}

// ruleTask is the task as the caller and approver rules see it.
func ruleTask(t *store.Task) map[string]any {
	items := make([]any, len(t.Items))
	for i, it := range t.Items {
		items[i] = map[string]any{
			"index":            it.Index,
			"resource":         it.Resource,
			"action":           it.Action,
			"requested_access": it.RequestedAccess,
			"status":           it.Status,
			"current_step":     it.CurrentStep,
		}
	}
	decisions := make([]any, len(t.Decisions))
	for i, d := range t.Decisions {
		decisions[i] = map[string]any{
			"item": d.ItemIndex, "step": d.Step, "approver": map[string]any{"iss": d.ApproverIss, "sub": d.ApproverSub},
			"decision": d.Decision, "decided_at": d.DecidedAt.UTC().Format(time.RFC3339),
		}
	}
	return map[string]any{
		"id":               t.ID,
		"status":           t.Status,
		"requester":        map[string]any{"iss": t.RequesterIss, "sub": t.RequesterSub, "client_id": t.RequesterClient},
		"subject":          t.Subject,
		"context":          t.Context,
		"requested_access": t.RequestedAccess,
		"client":           ruleClient(t.Client),
		"template":         t.Template,
		"evaluation_id":    t.EvaluationID,
		"bulk":             t.Bulk,
		"items":            items,
		"workflow":         t.Workflow,
		"current_step":     t.CurrentStep,
		"decisions":        decisions,
		"expires_at":       t.ExpiresAt.UTC().Format(time.RFC3339),
	}
}
