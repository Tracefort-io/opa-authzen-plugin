package ars

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
)

// plan is the parsed result of the workflow rule.
type plan struct {
	workflow store.Workflow
	auto     string // "", store.DecisionApprove or store.DecisionDeny
	display  map[string]any
}

// parsePlan validates the workflow rule's result. Anything malformed is a
// policy-authoring error: the task is not created and the request fails
// closed.
func parsePlan(v any) (*plan, error) {
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("workflow rule must return an object; got %T", v)
	}
	p := &plan{}
	if a, ok := obj["auto"]; ok {
		s, _ := a.(string)
		if s != store.DecisionApprove && s != store.DecisionDeny {
			return nil, fmt.Errorf(`workflow auto must be "approve" or "deny"`)
		}
		p.auto = s
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
	case len(p.workflow.Steps) == 0 && p.auto == "":
		return nil, fmt.Errorf("workflow must return steps or an auto decision")
	case len(p.workflow.Steps) > 1:
		return nil, fmt.Errorf("multi-step workflows are not supported in this version")
	}
	for i := range p.workflow.Steps {
		st := &p.workflow.Steps[i]
		if st.Name == "" {
			return nil, fmt.Errorf("workflow steps[%d].name is required", i)
		}
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

// approvedUntil is the lifetime given an approval granted now: the planned
// value, else the requester's requested_until, else the maximum, always
// capped at now + max.
func (s *Service) approvedUntil(t *store.Task, now time.Time, override *time.Time) time.Time {
	limit := now.Add(s.d.MaxApprovalTTL)
	until := limit
	if t.Workflow.ApprovedUntil != nil {
		until = *t.Workflow.ApprovedUntil
	} else if s, ok := t.RequestedAccess["requested_until"].(string); ok {
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
