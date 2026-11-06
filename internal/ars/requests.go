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

// submission is a parsed Access Request: one item, or several when the
// body carried `items` (Bulk Profile).
type submission struct {
	Subject         map[string]any
	Context         map[string]any
	RequestedAccess map[string]any
	Client          map[string]any
	Items           []subItem
	Bulk            bool
	Callback        *store.Callback
	// denial is the top-level denial; nil when every item carries its own.
	denial *denialEcho
	// actor is the verified client.actor, set after authentication.
	actor map[string]any
	body  map[string]any
}

// subItem is one requested Resource and Action.
type subItem struct {
	Resource        map[string]any
	Action          map[string]any
	RequestedAccess map[string]any
	// denial is the item's own denial, if it carries one.
	denial *denialEcho
}

// denialFor is the denial binding an item: its own, else the top-level one.
func (s *submission) denialFor(it *subItem) *denialEcho {
	if it.denial != nil {
		return it.denial
	}
	return s.denial
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

// parseDenial decodes a `denial` object. This service binds denials by a
// PDP-signed token only.
func parseDenial(raw any, name string) (*denialEcho, string) {
	b, _ := json.Marshal(raw)
	d := &denialEcho{}
	if _, ok := raw.(map[string]any); !ok || json.Unmarshal(b, d) != nil {
		return nil, name + " must be an object of strings"
	}
	if d.ExpiresAt == "" {
		return nil, name + ".expires_at is required"
	}
	if d.BindingToken == "" {
		return nil, name + ".binding_token is required"
	}
	return d, ""
}

// parseSubmission decodes and validates the body. It returns the problem to
// report, if any: (status, type, detail).
func (s *Service) parseSubmission(r *http.Request) (*submission, int, string, string) {
	var body map[string]any
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	if err := dec.Decode(&body); err != nil || body == nil {
		return nil, http.StatusBadRequest, problemGeneric, "the body must be a JSON object"
	}
	bad := func(detail string) (*submission, int, string, string) {
		return nil, http.StatusBadRequest, problemGeneric, detail
	}
	sub := &submission{body: body}
	var problem string
	if sub.Subject, problem = entity(body, "subject", "type", "id"); problem != "" {
		return bad(problem)
	}
	for name, dst := range map[string]*map[string]any{"context": &sub.Context, "requested_access": &sub.RequestedAccess, "client": &sub.Client} {
		if *dst, problem = object(body, name); problem != "" {
			return bad(problem)
		}
	}

	if raw, bulk := body["items"]; bulk {
		_, hasResource := body["resource"]
		_, hasAction := body["action"]
		if hasResource || hasAction {
			return bad("resource and action must be omitted when items is present")
		}
		list, ok := raw.([]any)
		if !ok || len(list) == 0 {
			return bad("items must be a non-empty array")
		}
		if len(list) > s.d.MaxItems {
			return bad(fmt.Sprintf("items lists %d items; at most %d are allowed", len(list), s.d.MaxItems))
		}
		sub.Bulk = true
		for i, e := range list {
			obj, ok := e.(map[string]any)
			if !ok {
				return bad(fmt.Sprintf("items[%d] must be a JSON object", i))
			}
			var it subItem
			name := fmt.Sprintf("items[%d]", i)
			if it.Resource, problem = entity(obj, "resource", "type", "id"); problem != "" {
				return bad(name + "." + problem)
			}
			if it.Action, problem = entity(obj, "action", "name"); problem != "" {
				return bad(name + "." + problem)
			}
			if it.RequestedAccess, problem = object(obj, "requested_access"); problem != "" {
				return bad(name + "." + problem)
			}
			if raw, has := obj["denial"]; has && raw != nil {
				if it.denial, problem = parseDenial(raw, name+".denial"); problem != "" {
					return nil, http.StatusBadRequest, ProblemInvalidBinding, problem
				}
			}
			sub.Items = append(sub.Items, it)
		}
	} else {
		var it subItem
		if it.Resource, problem = entity(body, "resource", "type", "id"); problem != "" {
			return bad(problem)
		}
		if it.Action, problem = entity(body, "action", "name"); problem != "" {
			return bad(problem)
		}
		sub.Items = []subItem{it}
	}

	if raw, has := body["denial"]; has && raw != nil {
		if sub.denial, problem = parseDenial(raw, "denial"); problem != "" {
			return nil, http.StatusBadRequest, ProblemInvalidBinding, problem
		}
	}
	for i := range sub.Items {
		if sub.denialFor(&sub.Items[i]) == nil {
			return nil, http.StatusBadRequest, ProblemNotRequestable, "the submission carries no denial"
		}
	}

	if raw, has := body["callback"]; has {
		if sub.Callback, problem = s.parseCallback(r.Context(), raw); problem != "" {
			return bad(problem)
		}
	}
	return sub, 0, "", ""
}

// object reads an optional JSON object member; null counts as absent.
func object(body map[string]any, name string) (map[string]any, string) {
	v, ok := body[name]
	if !ok || v == nil {
		return nil, ""
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, name + " must be a JSON object"
	}
	return m, ""
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
// client.actor appears only once verified, flagged actor_verified;
// client.source never does, since nothing can verify it (ARAP "Submission
// Processing").
func ruleSubmission(sub *submission) map[string]any {
	var client map[string]any
	if sub.Client != nil {
		client = map[string]any{}
		for k, v := range sub.Client {
			if k != "actor" && k != "source" {
				client[k] = v
			}
		}
		if sub.actor != nil {
			client["actor"], client["actor_verified"] = sub.actor, true
		}
	}
	items := make([]any, len(sub.Items))
	for i := range sub.Items {
		it := &sub.Items[i]
		items[i] = map[string]any{
			"resource": it.Resource, "action": it.Action,
			"requested_access": mergeMaps(sub.RequestedAccess, it.RequestedAccess),
			"denial":           ruleDenial(sub.denialFor(it)),
		}
	}
	out := map[string]any{
		"subject":          sub.Subject,
		"items":            items,
		"bulk":             sub.Bulk,
		"context":          sub.Context,
		"requested_access": sub.RequestedAccess,
		"client":           client,
		"denial":           ruleDenial(sub.denialFor(&sub.Items[0])),
	}
	if sub.denial != nil {
		out["denial"] = ruleDenial(sub.denial)
	}
	if sub.Callback != nil {
		out["callback"] = map[string]any{"endpoint": sub.Callback.Endpoint, "events": sub.Callback.Events}
	}
	return out
}

func ruleDenial(d *denialEcho) map[string]any {
	return map[string]any{"template": d.Template, "reason": d.Reason, "evaluation_id": d.EvaluationID, "expires_at": d.ExpiresAt}
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

// verifyDenials verifies each item's binding_token. A token may bind only
// one item. It returns the verified denials, in item order, or the problem.
func (s *Service) verifyDenials(sub *submission) ([]*verifiedDenial, int, string, string) {
	out := make([]*verifiedDenial, len(sub.Items))
	seen := map[string]bool{}
	for i := range sub.Items {
		it := &sub.Items[i]
		claims, err := s.d.Crypto.VerifyBindingToken(sub.denialFor(it).BindingToken)
		if err != nil {
			return nil, http.StatusBadRequest, ProblemInvalidBinding, itemDetail(sub, i, "binding_token does not verify")
		}
		v, err := s.verifyBinding(claims, sub, it)
		switch {
		case errors.Is(err, errExpiredDenial):
			return nil, http.StatusGone, ProblemExpiredDenial, itemDetail(sub, i, "the denial has expired")
		case err != nil:
			return nil, http.StatusBadRequest, ProblemInvalidBinding, itemDetail(sub, i, err.Error())
		}
		if seen[v.jti] {
			return nil, http.StatusBadRequest, ProblemInvalidBinding, itemDetail(sub, i, "binding_token already binds another item")
		}
		seen[v.jti] = true
		out[i] = v
	}
	return out, 0, "", ""
}

func itemDetail(sub *submission, i int, detail string) string {
	if sub.Bulk {
		return fmt.Sprintf("items[%d]: %s", i, detail)
	}
	return detail
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
	// Actor Profile: a claimed chain the caller's credential does not
	// authorize is rejected.
	if sub.actor, err = verifyActor(caller, sub); err != nil {
		writeProblem(w, http.StatusForbidden, problemGeneric, "Actor chain not verified", err.Error())
		return
	}
	denials, status, typ, detail := s.verifyDenials(sub)
	if denials == nil {
		title := "Invalid denial binding"
		if typ == ProblemExpiredDenial {
			title = "Requestable denial has expired"
		}
		writeProblem(w, status, typ, title, detail)
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
	p, err := parsePlan(raw, len(sub.Items), s.d.MaxSteps)
	if err != nil {
		s.d.Logger.Error("AuthZEN access request: workflow rule result: %v", err)
		internalError(w)
		return
	}

	now := s.now()
	task, approvals := s.buildTask(caller, sub, denials, p, now)
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
	jtis := make([]store.JTI, len(denials))
	for i, d := range denials {
		jtis[i] = store.JTI{ID: d.jti, Expires: d.exp.Add(clockSkew)}
	}
	stored, existed, err := s.d.Store.CreateTask(ctx, &store.NewTask{
		Task:        task,
		Approvals:   approvals,
		Idempotency: idem,
		JTIs:        jtis,
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
// the approvals of the items the plan auto-approves.
func (s *Service) buildTask(caller *authn.Identity, sub *submission, denials []*verifiedDenial, p *plan, now time.Time) (*store.Task, []*store.Approval) {
	first := denials[0].record()
	evalID, _ := first["evaluation_id"].(string)
	template := denials[0].echo.Template
	if sub.denial != nil && sub.denial.Template != "" {
		template = sub.denial.Template
	}
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
		Denial:          first,
		Template:        template,
		EvaluationID:    evalID,
		Workflow:        p.workflow,
		Display:         p.display,
		Bulk:            sub.Bulk,
		Callback:        sub.Callback,
		ExpiresAt:       now.Add(s.d.TaskTTL).Truncate(time.Second),
		CreatedAt:       now,
	}
	for i, it := range sub.Items {
		t.Items = append(t.Items, store.Item{
			Index: i, Resource: it.Resource, Action: it.Action, RequestedAccess: it.RequestedAccess,
			Status: store.StatusPending, Denial: denials[i].record(),
		})
	}
	var approvals []*store.Approval
	for i, auto := range p.auto {
		switch auto {
		case store.DecisionApprove:
			a := s.newApproval(t, i, now, nil)
			approvals = append(approvals, a)
			t.Items[i].Status, t.Items[i].ApprovalID = store.StatusApproved, a.ID
		case store.DecisionDeny:
			t.Items[i].Status = store.StatusDenied
		}
	}
	t.Status = store.Aggregate(t.Items)
	if store.IsTerminal(t.Status) {
		t.CompletedAt = &now
	}
	return t, approvals
}

// itemBinding is what an item's approval is scoped to beyond the subject,
// resource and action: the denial's binding context members and the bound
// context. Tasks stored before denials were kept per item use the task's.
func itemBinding(t *store.Task, item int) ([]string, map[string]any) {
	d := t.Items[item].Denial
	if d == nil {
		d = t.Denial
	}
	ctx, _ := d["context"].(map[string]any)
	return stringList(d["binding_context_members"]), ctx
}

// stringList reads a list of strings that JSON round trips may leave as
// []any.
func stringList(v any) []string {
	switch m := v.(type) {
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

// newApproval records what an approved item grants: the denied request it
// was bound to, with the actor removed, and its lifetime.
func (s *Service) newApproval(t *store.Task, item int, now time.Time, override *time.Time) *store.Approval {
	it := t.Items[item]
	members, ctxMap := itemBinding(t, item)
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
		ApprovedUntil:         s.approvedUntil(t, item, now, override),
	}
}

// writeTask writes a task handle with its results. From submission, a
// terminal task is 201 and a pending one 202.
func (s *Service) writeTask(ctx context.Context, w http.ResponseWriter, t *store.Task, fromSubmit bool) {
	body, err := s.render(ctx, t)
	if err != nil {
		s.d.Logger.Error("AuthZEN access request: building result: %v", err)
		internalError(w)
		return
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
// "Cancellation"). Pending items are cancelled and completed ones kept, so
// a bulk task with items completed first becomes partial.
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
		statuses := map[int]string{}
		for i := range cur.Items {
			if cur.Items[i].Status == store.StatusPending {
				cur.Items[i].Status = store.StatusCancelled
				statuses[cur.Items[i].Index] = store.StatusCancelled
			}
		}
		return &store.Change{Status: store.Aggregate(cur.Items), CompletedAt: &now, ItemStatus: statuses}, nil
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
	s.writeTask(r.Context(), w, updated, false)
}

// auditTask is the common content of an audit record about a task. A bulk
// task lists its items; a single-item task names its resource and action.
func (s *Service) auditTask(t *store.Task, actor *authn.Identity) map[string]any {
	attrs := map[string]any{
		"task_id":       t.ID,
		"status":        t.Status,
		"evaluation_id": t.EvaluationID,
		"subject":       t.Subject,
		"requester":     t.RequesterIss + "|" + t.RequesterSub,
	}
	if a, ok := t.Client["actor"]; ok {
		attrs["client_actor"] = a
	}
	if src, ok := t.Client["source"]; ok {
		attrs["client_source"] = src
	}
	switch {
	case t.Bulk:
		items := make([]any, len(t.Items))
		for i, it := range t.Items {
			items[i] = map[string]any{"idx": it.Index, "resource": it.Resource, "action": it.Action, "status": it.Status, "approval_id": it.ApprovalID}
		}
		attrs["items"] = items
	case len(t.Items) > 0:
		attrs["resource"], attrs["action"] = t.Items[0].Resource, t.Items[0].Action
		if t.Items[0].ApprovalID != "" {
			attrs["approval_id"] = t.Items[0].ApprovalID
		}
	}
	if actor != nil {
		attrs["actor"] = actor.Key()
	} else {
		attrs["actor"] = "system"
	}
	return attrs
}
