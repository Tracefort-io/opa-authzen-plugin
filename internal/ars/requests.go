package ars

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
	"github.com/Tracefort-io/opa-authzen-plugin/internal/authn"
	"github.com/google/uuid"
)

// submission is a parsed single-item Access Request.
type submission struct {
	Subject         map[string]any
	Resource        map[string]any
	Action          map[string]any
	Context         map[string]any
	RequestedAccess map[string]any
	Client          map[string]any
	denial          denialEcho
	body            map[string]any
}

// denialEcho is the submission's `denial` object (ARAP "The denial Object").
type denialEcho struct {
	ExpiresAt    string `json:"expires_at"`
	EvaluationID string `json:"evaluation_id,omitempty"`
	BindingToken string `json:"binding_token,omitempty"`
	EvaluatedAt  string `json:"evaluated_at,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Template     string `json:"template,omitempty"`
}

// parseSubmission decodes and validates the body. It returns the problem to
// report, if any: (status, type, detail).
func (s *Service) parseSubmission(r *http.Request) (*submission, int, string, string) {
	var body map[string]any
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	if err := dec.Decode(&body); err != nil || body == nil {
		return nil, http.StatusBadRequest, problemGeneric, "the body must be a JSON object"
	}
	if _, ok := body["items"]; ok {
		return nil, http.StatusBadRequest, problemGeneric, "items is not supported"
	}
	if _, ok := body["callback"]; ok {
		// The Callback Profile treats the Task Status Endpoint as
		// authoritative, so a PEP that also polls loses nothing.
		s.d.Logger.Warn("AuthZEN access request: callback is not supported in this version and was ignored")
	}
	sub := &submission{body: body}
	var problem string
	if sub.Subject, problem = entity(body, "subject", "type", "id"); problem != "" {
		return nil, http.StatusBadRequest, problemGeneric, problem
	}
	if sub.Resource, problem = entity(body, "resource", "type", "id"); problem != "" {
		return nil, http.StatusBadRequest, problemGeneric, problem
	}
	if sub.Action, problem = entity(body, "action", "name"); problem != "" {
		return nil, http.StatusBadRequest, problemGeneric, problem
	}
	for name, dst := range map[string]*map[string]any{"context": &sub.Context, "requested_access": &sub.RequestedAccess, "client": &sub.Client} {
		v, ok := body[name]
		if !ok || v == nil {
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, http.StatusBadRequest, problemGeneric, name + " must be a JSON object"
		}
		*dst = m
	}
	raw, ok := body["denial"]
	if !ok || raw == nil {
		return nil, http.StatusBadRequest, ProblemNotRequestable, "the submission carries no denial"
	}
	b, _ := json.Marshal(raw)
	if err := json.Unmarshal(b, &sub.denial); err != nil {
		return nil, http.StatusBadRequest, ProblemInvalidBinding, "denial must be an object of strings"
	}
	if sub.denial.ExpiresAt == "" {
		return nil, http.StatusBadRequest, ProblemInvalidBinding, "denial.expires_at is required"
	}
	// This service binds denials by a PDP-signed token only.
	if sub.denial.BindingToken == "" {
		return nil, http.StatusBadRequest, ProblemInvalidBinding, "denial.binding_token is required"
	}
	return sub, 0, "", ""
}

// entity validates an AuthZEN entity member: an object with the named
// required string members and, if present, an object `properties`.
func entity(body map[string]any, name string, required ...string) (map[string]any, string) {
	m, ok := body[name].(map[string]any)
	if !ok {
		return nil, name + " is required and must be a JSON object"
	}
	for _, f := range required {
		if s, ok := m[f].(string); !ok || s == "" {
			return nil, fmt.Sprintf("%s.%s is required and must be a string", name, f)
		}
	}
	if p, ok := m["properties"]; ok {
		if p == nil {
			delete(m, "properties")
		} else if _, ok := p.(map[string]any); !ok {
			return nil, name + ".properties must be a JSON object"
		}
	}
	return m, ""
}

func callerInput(id *authn.Identity) map[string]any {
	return map[string]any{
		"iss":       id.Iss,
		"sub":       id.Sub,
		"client_id": id.ClientID,
		"act":       id.Act,
		"claims":    id.Claims,
	}
}

// ruleSubmission is the submission as the caller and workflow rules see it.
// client.actor and client.source are left out: ARAP forbids relying on them
// unless verified, which this version does not do.
func ruleSubmission(sub *submission) map[string]any {
	var client map[string]any
	if sub.Client != nil {
		client = map[string]any{}
		for k, v := range sub.Client {
			if k != "actor" && k != "source" {
				client[k] = v
			}
		}
	}
	return map[string]any{
		"subject":          sub.Subject,
		"items":            []any{map[string]any{"resource": sub.Resource, "action": sub.Action, "requested_access": sub.RequestedAccess}},
		"context":          sub.Context,
		"requested_access": sub.RequestedAccess,
		"client":           client,
		"denial": map[string]any{
			"template": sub.denial.Template, "reason": sub.denial.Reason,
			"evaluation_id": sub.denial.EvaluationID, "expires_at": sub.denial.ExpiresAt,
		},
	}
}

// allowed evaluates a boolean authorization rule; anything but true denies.
func (s *Service) allowed(ctx context.Context, rule string, input map[string]any) (bool, error) {
	v, err := s.d.Eval(ctx, rule, input)
	if err != nil {
		return false, err
	}
	b, _ := v.(bool)
	return b, nil
}

func newID(prefix string) string {
	if id, err := uuid.NewV7(); err == nil {
		return prefix + id.String()
	}
	return prefix + uuid.NewString()
}

// handleSubmit serves POST /access/v1/requests (ARAP "Access Request
// Submission").
func (s *Service) handleSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	caller, err := s.d.Callers.Authenticate(r)
	if err != nil {
		unauthenticated(w)
		return
	}
	sub, status, typ, detail := s.parseSubmission(r)
	if sub == nil {
		writeProblem(w, status, typ, "Invalid access request", detail)
		return
	}

	claims, err := s.d.Crypto.VerifyBindingToken(sub.denial.BindingToken)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, ProblemInvalidBinding, "Invalid denial binding", "binding_token does not verify")
		return
	}
	denial, err := s.verifyBinding(claims, sub)
	switch {
	case errors.Is(err, errExpiredDenial):
		writeProblem(w, http.StatusGone, ProblemExpiredDenial, "Requestable denial has expired", "")
		return
	case err != nil:
		writeProblem(w, http.StatusBadRequest, ProblemInvalidBinding, "Invalid denial binding", err.Error())
		return
	}

	in := map[string]any{"operation": "submit", "caller": callerInput(caller), "submission": ruleSubmission(sub)}
	ok, err := s.allowed(ctx, s.d.Rules.Caller, in)
	if err != nil {
		s.d.Logger.Error("AuthZEN access request: caller rule: %v", err)
		internalError(w)
		return
	}
	if !ok {
		forbidden(w)
		return
	}

	in["operation"] = "plan"
	raw, err := s.d.Eval(ctx, s.d.Rules.Workflow, in)
	if err != nil {
		s.d.Logger.Error("AuthZEN access request: workflow rule: %v", err)
		internalError(w)
		return
	}
	p, err := parsePlan(raw)
	if err != nil {
		s.d.Logger.Error("AuthZEN access request: workflow rule result: %v", err)
		internalError(w)
		return
	}

	now := s.now()
	task, approvals := s.buildTask(caller, sub, denial, p, now)
	var idem store.Idempotency
	if key := r.Header.Get("Idempotency-Key"); key != "" {
		canon, _ := json.Marshal(sub.body)
		hash := sha256.Sum256(canon)
		idem = store.Idempotency{
			Requester:   caller.Key(),
			Key:         key,
			BodyHash:    hash[:],
			RetainUntil: task.ExpiresAt.Add(s.d.IdempotencyRetention),
		}
	}
	stored, existed, err := s.d.Store.CreateTask(ctx, &store.NewTask{
		Task:        task,
		Approvals:   approvals,
		Idempotency: idem,
		JTI:         denial.jti,
		JTIExpires:  denial.exp.Add(clockSkew),
	}, now)
	switch {
	case errors.Is(err, store.ErrDuplicateRequest):
		writeProblem(w, http.StatusConflict, ProblemDuplicate, "Idempotency-Key reused", "the key was used with a different request")
		return
	case errors.Is(err, store.ErrReplay):
		writeProblem(w, http.StatusBadRequest, ProblemInvalidBinding, "Invalid denial binding", "binding_token has already been used")
		return
	case err != nil:
		s.d.Logger.Error("AuthZEN access request: storing task: %v", err)
		internalError(w)
		return
	}
	if !existed {
		s.d.Audit.Emit(ctx, "submitted", s.auditTask(stored, caller))
		if store.IsTerminal(stored.Status) {
			s.d.Audit.Emit(ctx, stored.Status, s.auditTask(stored, caller))
		}
	}
	s.writeTask(ctx, w, stored, true)
}

// buildTask turns a verified submission and its plan into a task, and into
// the approval when the plan auto-approves.
func (s *Service) buildTask(caller *authn.Identity, sub *submission, denial *verifiedDenial, p *plan, now time.Time) (*store.Task, []*store.Approval) {
	evalID, _ := denial.claims["evaluation_id"].(string)
	t := &store.Task{
		ID:              newID("arq_"),
		Status:          store.StatusPending,
		RequesterIss:    caller.Iss,
		RequesterSub:    caller.Sub,
		RequesterClient: caller.ClientID,
		Subject:         sub.Subject,
		Context:         sub.Context,
		RequestedAccess: sub.RequestedAccess,
		Client:          sub.Client,
		Denial: map[string]any{
			"expires_at": sub.denial.ExpiresAt, "evaluation_id": evalID, "evaluated_at": sub.denial.EvaluatedAt,
			"reason": sub.denial.Reason, "template": sub.denial.Template,
			"binding_context_members": denial.members, "context": denial.claims["context"],
		},
		Template:     sub.denial.Template,
		EvaluationID: evalID,
		Workflow:     p.workflow,
		Display:      p.display,
		Items: []store.Item{{
			Index: 0, Resource: sub.Resource, Action: sub.Action,
			RequestedAccess: sub.RequestedAccess, Status: store.StatusPending,
		}},
		ExpiresAt: now.Add(s.d.TaskTTL).Truncate(time.Second),
		CreatedAt: now,
	}
	var approvals []*store.Approval
	switch p.auto {
	case store.DecisionApprove:
		a := s.newApproval(t, 0, denial.members, now, nil)
		approvals = append(approvals, a)
		t.Status, t.Items[0].Status, t.Items[0].ApprovalID = store.StatusApproved, store.StatusApproved, a.ID
		t.CompletedAt = &now
	case store.DecisionDeny:
		t.Status, t.Items[0].Status = store.StatusDenied, store.StatusDenied
		t.CompletedAt = &now
	}
	return t, approvals
}

// newApproval records what an approved item grants: the denied request it
// was bound to, with the actor removed, and its lifetime.
func (s *Service) newApproval(t *store.Task, item int, members []string, now time.Time, override *time.Time) *store.Approval {
	it := t.Items[item]
	ctxMap, _ := t.Denial["context"].(map[string]any)
	return &store.Approval{
		ID:                    newID("apr_"),
		TaskID:                t.ID,
		ItemIndex:             item,
		Subject:               WithoutActor(t.Subject).(map[string]any),
		Resource:              it.Resource,
		Action:                it.Action,
		BindingContextMembers: members,
		Context:               ctxMap,
		ApprovedAt:            now.Truncate(time.Second),
		ApprovedUntil:         s.approvedUntil(t, now, override),
	}
}

// writeTask writes a task handle and, for an approved task, its result.
// From submission, a terminal task is 201 and a pending one 202.
func (s *Service) writeTask(ctx context.Context, w http.ResponseWriter, t *store.Task, fromSubmit bool) {
	res, err := s.result(ctx, t)
	if err != nil {
		s.d.Logger.Error("AuthZEN access request: building result: %v", err)
		internalError(w)
		return
	}
	body := map[string]any{"task": s.taskHandle(t)}
	if res != nil {
		body["result"] = res
	}
	status := http.StatusOK
	if fromSubmit {
		w.Header().Set("Location", s.statusEndpoint(t.ID))
		status = http.StatusAccepted
		if store.IsTerminal(t.Status) {
			status = http.StatusCreated
		}
	}
	writeJSON(w, status, body)
}

// loadAuthorized authenticates the caller, loads the task and checks the
// caller rule for op. A task the caller may not see is reported as unknown.
func (s *Service) loadAuthorized(w http.ResponseWriter, r *http.Request, op string) (*store.Task, *authn.Identity, bool) {
	caller, err := s.d.Callers.Authenticate(r)
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
		s.d.Logger.Error("AuthZEN access request: loading task: %v", err)
		internalError(w)
		return nil, nil, false
	}
	ok, err := s.allowed(r.Context(), s.d.Rules.Caller, map[string]any{"operation": op, "caller": callerInput(caller), "task": ruleTask(t)})
	if err != nil {
		s.d.Logger.Error("AuthZEN access request: caller rule: %v", err)
		internalError(w)
		return nil, nil, false
	}
	if !ok {
		unknownTask(w)
		return nil, nil, false
	}
	return t, caller, true
}

// handleStatus serves GET /access/v1/requests/{id} (ARAP "Task Status
// Endpoint").
func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	t, _, ok := s.loadAuthorized(w, r, "view")
	if !ok {
		return
	}
	if store.IsTerminal(t.Status) && s.now().After(t.ExpiresAt.Add(s.d.IdempotencyRetention)) {
		writeProblem(w, http.StatusGone, ProblemTaskExpired, "Task has expired", "")
		return
	}
	s.writeTask(r.Context(), w, t, false)
}

// handleCancel serves POST and DELETE /access/v1/requests/{id}/cancel (ARAP
// "Cancellation").
func (s *Service) handleCancel(w http.ResponseWriter, r *http.Request) {
	t, caller, ok := s.loadAuthorized(w, r, "cancel")
	if !ok {
		return
	}
	var body struct {
		Reason  string `json:"reason"`
		Comment string `json:"comment"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&body); err != nil {
			badRequest(w, "the body must be a JSON object")
			return
		}
	}
	now := s.now()
	updated, err := s.d.Store.UpdateTask(r.Context(), t.ID, func(cur *store.Task) (*store.Change, error) {
		if store.IsTerminal(cur.Status) {
			return nil, store.ErrConflict
		}
		items := map[int]string{}
		for _, it := range cur.Items {
			if it.Status == store.StatusPending {
				items[it.Index] = store.StatusCancelled
			}
		}
		return &store.Change{Status: store.StatusCancelled, CompletedAt: &now, ItemStatus: items}, nil
	})
	switch {
	case errors.Is(err, store.ErrConflict):
		writeProblem(w, http.StatusConflict, ProblemInvalidState, "Task is already complete", "")
		return
	case err != nil:
		s.d.Logger.Error("AuthZEN access request: cancelling task: %v", err)
		internalError(w)
		return
	}
	attrs := s.auditTask(updated, caller)
	attrs["reason"], attrs["comment"] = body.Reason, body.Comment
	s.d.Audit.Emit(r.Context(), "cancelled", attrs)
	writeJSON(w, http.StatusOK, map[string]any{"task": s.taskHandle(updated)})
}

// auditTask is the common content of an audit record about a task.
func (s *Service) auditTask(t *store.Task, actor *authn.Identity) map[string]any {
	attrs := map[string]any{
		"task_id":       t.ID,
		"status":        t.Status,
		"evaluation_id": t.EvaluationID,
		"subject":       t.Subject,
		"requester":     t.RequesterIss + "|" + t.RequesterSub,
	}
	if len(t.Items) > 0 {
		attrs["resource"], attrs["action"] = t.Items[0].Resource, t.Items[0].Action
		if t.Items[0].ApprovalID != "" {
			attrs["approval_id"] = t.Items[0].ApprovalID
		}
	}
	if actor != nil {
		attrs["actor"] = actor.Key()
	}
	return attrs
}
