package ars

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
)

// plan is the parsed result of the workflow rule.
type plan struct {
	workflow store.Workflow
	// auto holds, per item, "" (left to the approvers),
	// store.DecisionApprove or store.DecisionDeny.
	auto    []string
	display map[string]any
}

// parsePlan validates the workflow rule's result for a submission of
// nItems items. Anything malformed is a policy-authoring error: the task is
// not created and the request fails closed.
func parsePlan(v any, nItems, maxSteps int) (*plan, error) {
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("workflow rule must return an object; got %T", v)
	}
	p := &plan{auto: make([]string, nItems)}
	isDecision := func(s string) bool { return s == store.DecisionApprove || s == store.DecisionDeny }
	switch a := obj["auto"].(type) {
	case nil:
		if _, has := obj["auto"]; has {
			return nil, fmt.Errorf("workflow auto must not be null")
		}
	case string:
		if !isDecision(a) {
			return nil, fmt.Errorf(`workflow auto must be "approve" or "deny"`)
		}
		for i := range p.auto {
			p.auto[i] = a
		}
	case []any:
		// One decision per item, null leaving that item to the approvers.
		if len(a) != nItems {
			return nil, fmt.Errorf("workflow auto lists %d decisions for %d items", len(a), nItems)
		}
		for i, e := range a {
			if e == nil {
				continue
			}
			s, _ := e.(string)
			if !isDecision(s) {
				return nil, fmt.Errorf(`workflow auto[%d] must be "approve", "deny" or null`, i)
			}
			p.auto[i] = s
		}
	default:
		return nil, fmt.Errorf("workflow auto must be a string or an array")
	}
	if d, ok := obj["display"]; ok {
		m, ok := d.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("workflow display must be an object")
		}
		p.display = m
	}
	if u, ok := obj["approved_until"]; ok {
		s, _ := u.(string)
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return nil, fmt.Errorf("workflow approved_until must be an RFC 3339 timestamp")
		}
		p.workflow.ApprovedUntil = &t
	}
	if raw, ok := obj["steps"]; ok {
		b, err := json.Marshal(raw)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &p.workflow.Steps); err != nil {
			return nil, fmt.Errorf("workflow steps: %w", err)
		}
	}
	switch {
	case len(p.workflow.Steps) == 0 && slices.Contains(p.auto, ""):
		return nil, fmt.Errorf("workflow must return steps or an auto decision for every item")
	case len(p.workflow.Steps) > maxSteps:
		return nil, fmt.Errorf("workflow returns %d steps; at most %d are allowed", len(p.workflow.Steps), maxSteps)
	}
	names := map[string]bool{}
	for i := range p.workflow.Steps {
		st := &p.workflow.Steps[i]
		if st.Name == "" {
			return nil, fmt.Errorf("workflow steps[%d].name is required", i)
		}
		if names[st.Name] {
			return nil, fmt.Errorf("workflow step name %q is used twice", st.Name)
		}
		names[st.Name] = true
		if st.Required == 0 {
			st.Required = 1
		}
		if st.Required < 0 {
			return nil, fmt.Errorf("workflow steps[%d].required must be positive", i)
		}
		if len(st.Approvers) < st.Required {
			return nil, fmt.Errorf("workflow steps[%d] lists %d approvers but requires %d", i, len(st.Approvers), st.Required)
		}
		for j, a := range st.Approvers {
			typ, _ := a["type"].(string)
			id, _ := a["id"].(string)
			if typ == "" || id == "" {
				return nil, fmt.Errorf("workflow steps[%d].approvers[%d] needs a string type and id", i, j)
			}
		}
	}
	return p, nil
}

// approvedUntil is the lifetime given an item's approval granted now: the
// planned value, else the item's requested_until, else the maximum, always
// capped at now + max. override, the shortest lifetime an approver gave,
// can only shorten it.
func (s *Service) approvedUntil(t *store.Task, item int, now time.Time, override *time.Time) time.Time {
	limit := now.Add(s.d.MaxApprovalTTL)
	until := limit
	if t.Workflow.ApprovedUntil != nil {
		until = *t.Workflow.ApprovedUntil
	} else if s, ok := requestedAccess(t, item)["requested_until"].(string); ok {
		if r, err := time.Parse(time.RFC3339, s); err == nil {
			until = r
		}
	}
	if override != nil && override.Before(until) {
		until = *override
	}
	if until.After(limit) {
		until = limit
	}
	return until.Truncate(time.Second)
}

// requestedAccess is an item's requested_access merged over the task's,
// item values taking precedence (Bulk Profile "Request Items").
func requestedAccess(t *store.Task, item int) map[string]any {
	return mergeMaps(t.RequestedAccess, t.Items[item].RequestedAccess)
}

func mergeMaps(base, over map[string]any) map[string]any {
	if over == nil {
		return base
	}
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

// shortestOverride is the earliest approved_until any approver of the item
// gave, including next, the one being recorded.
func shortestOverride(t *store.Task, item int, next *time.Time) *time.Time {
	shortest := next
	for _, d := range t.Decisions {
		if d.ItemIndex == item && d.ApprovedUntil != nil && (shortest == nil || d.ApprovedUntil.Before(*shortest)) {
			shortest = d.ApprovedUntil
		}
	}
	return shortest
}
