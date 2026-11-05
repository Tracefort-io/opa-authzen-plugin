package ars

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
)

// taskHandle renders the ARAP Task Handle a PEP sees.
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
	if t.Status == store.StatusPending && t.CurrentStep < len(t.Workflow.Steps) {
		step := t.Workflow.Steps[t.CurrentStep]
		progress := map[string]any{
			"current_step": t.CurrentStep + 1,
			"total_steps":  len(t.Workflow.Steps),
			"step_name":    step.Name,
		}
		// Approver identities are disclosed only where the workflow allows
		// it (ARAP "Privacy Considerations").
		if step.DiscloseApprovers {
			awaiting := []string{}
			for _, a := range step.Approvers {
				id, _ := a["id"].(string)
				if !decided(t, t.CurrentStep, id) {
					awaiting = append(awaiting, id)
				}
			}
			progress["awaiting"] = awaiting
		}
		h["progress"] = progress
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

func decided(t *store.Task, step int, sub string) bool {
	return slices.ContainsFunc(t.Decisions, func(d store.Decision) bool { return d.Step == step && d.ApproverSub == sub })
}

// result renders the completion result of an approved task (ARAP
// "Approval Result"): re-evaluate, with the approval and a signed
// approval.state other PDPs trusting this one can verify.
func (s *Service) result(ctx context.Context, t *store.Task) (map[string]any, error) {
	if t.Status != store.StatusApproved || len(t.Items) == 0 || t.Items[0].ApprovalID == "" {
		return nil, nil
	}
	a, err := s.d.Store.GetApproval(ctx, t.Items[0].ApprovalID)
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
// signed-approval verification reads.
func (s *Service) approvalClaims(a *store.Approval) map[string]any {
	return map[string]any{
		"iss":                     s.d.BaseURL,
		"aud":                     s.d.BaseURL,
		"exp":                     a.ApprovedUntil.Unix(),
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

// ruleTask is the task as the caller and approver rules see it.
func ruleTask(t *store.Task) map[string]any {
	items := make([]any, len(t.Items))
	for i, it := range t.Items {
		items[i] = map[string]any{
			"resource":         it.Resource,
			"action":           it.Action,
			"requested_access": it.RequestedAccess,
			"status":           it.Status,
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
		"client":           t.Client,
		"template":         t.Template,
		"evaluation_id":    t.EvaluationID,
		"items":            items,
		"workflow":         t.Workflow,
		"current_step":     t.CurrentStep,
		"decisions":        decisions,
		"expires_at":       t.ExpiresAt.UTC().Format(time.RFC3339),
	}
}
