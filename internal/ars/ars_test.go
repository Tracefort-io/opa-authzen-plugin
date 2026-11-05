package ars

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
	"github.com/Tracefort-io/opa-authzen-plugin/internal/authn"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

const (
	baseURL   = "https://pdp.example.com"
	idpIssuer = "https://idp.example.com"
)

var now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T, kid string) jwk.Key {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := jwk.Import(raw)
	if err != nil {
		t.Fatal(err)
	}
	_ = k.Set(jwk.KeyIDKey, kid)
	_ = k.Set(jwk.AlgorithmKey, jwa.ES256())
	return k
}

func signJWT(t *testing.T, key jwk.Key, claims map[string]any) string {
	t.Helper()
	payload, _ := json.Marshal(claims)
	hdr := jws.NewHeaders()
	kid, _ := key.KeyID()
	_ = hdr.Set(jws.KeyIDKey, kid)
	out, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// testCrypto signs and verifies with one key, as the PDP does.
type testCrypto struct{ key jwk.Key }

func (c testCrypto) VerifyBindingToken(token string) (map[string]any, error) {
	pub, _ := c.key.PublicKey()
	payload, err := jws.Verify([]byte(token), jws.WithKey(jwa.ES256(), pub))
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	err = json.Unmarshal(payload, &claims)
	return claims, err
}

func (c testCrypto) SignApprovalState(claims map[string]any) (string, error) {
	payload, _ := json.Marshal(claims)
	out, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), c.key))
	return string(out), err
}

type recordedAudit struct{ events []string }

func (a *recordedAudit) Emit(_ context.Context, event string, _ map[string]any) {
	a.events = append(a.events, event)
}

type fixture struct {
	svc    *Service
	store  *store.Memory
	pdpKey jwk.Key
	idpKey jwk.Key
	audit  *recordedAudit
	rules  map[string]func(map[string]any) any
	mux    *http.ServeMux
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{store: store.NewMemory(), pdpKey: newKey(t, "pdp-1"), idpKey: newKey(t, "idp-1"), audit: &recordedAudit{}}
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pub, _ := f.idpKey.PublicKey()
		set := jwk.NewSet()
		_ = set.AddKey(pub)
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(idp.Close)
	callers, err := authn.NewVerifier([]authn.Issuer{{Issuer: idpIssuer, Audience: baseURL, JWKSURI: idp.URL}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	approvers, err := authn.NewVerifier([]authn.Issuer{{Issuer: idpIssuer, Audience: "approver-api", JWKSURI: idp.URL}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Default policy: requesters may act on their own tasks; one manager
	// approves; approvers may act on tasks they are listed on.
	f.rules = map[string]func(map[string]any) any{
		"ars_caller": func(in map[string]any) any {
			caller := in["caller"].(map[string]any)
			if in["operation"] == "submit" {
				return true
			}
			req := in["task"].(map[string]any)["requester"].(map[string]any)
			return req["sub"] == caller["sub"]
		},
		"ars_workflow": func(map[string]any) any {
			return map[string]any{"steps": []any{map[string]any{
				"name": "manager_approval", "required": 1,
				"approvers": []any{map[string]any{"type": "user", "id": "manager"}},
			}}}
		},
		"ars_approver": func(map[string]any) any { return true },
	}
	f.svc = New(&Deps{
		Store: f.store, Callers: callers, Approvers: approvers,
		Eval: func(_ context.Context, rule string, in map[string]any) (any, error) {
			fn, ok := f.rules[rule]
			if !ok {
				return nil, errors.New("no such rule " + rule)
			}
			return fn(in), nil
		},
		Crypto:               testCrypto{key: f.pdpKey},
		Rules:                Rules{Caller: "ars_caller", Workflow: "ars_workflow", Approver: "ars_approver"},
		BaseURL:              baseURL,
		Audience:             baseURL,
		TaskTTL:              72 * time.Hour,
		MaxApprovalTTL:       30 * 24 * time.Hour,
		IdempotencyRetention: 24 * time.Hour,
		Audit:                f.audit,
		Now:                  func() time.Time { return now },
	})
	f.mux = http.NewServeMux()
	for pattern, h := range f.svc.Routes() {
		f.mux.HandleFunc(pattern, h)
	}
	return f
}

// callerToken is an access token for a PEP or agent runtime.
func (f *fixture) callerToken(t *testing.T, sub string) string {
	return signJWT(t, f.idpKey, map[string]any{"iss": idpIssuer, "aud": baseURL, "sub": sub, "exp": float64(time.Now().Add(time.Hour).Unix())})
}

func (f *fixture) approverToken(t *testing.T, sub string) string {
	return signJWT(t, f.idpKey, map[string]any{"iss": idpIssuer, "aud": "approver-api", "sub": sub, "exp": float64(time.Now().Add(time.Hour).Unix())})
}

// bindingClaims are the claims of a binding_token for the standard denial.
func bindingClaims() map[string]any {
	return map[string]any{
		"iss":                     baseURL,
		"aud":                     baseURL,
		"iat":                     float64(now.Add(-time.Minute).Unix()),
		"exp":                     float64(now.Add(9 * time.Minute).Unix()),
		"jti":                     "jti-1",
		"denial_expires_at":       now.Add(9 * time.Minute).Format(time.RFC3339),
		"evaluation_id":           "eval_1",
		"binding_context_members": []any{"project"},
		"subject":                 map[string]any{"type": "user", "id": "alice"},
		"resource":                map[string]any{"type": "document", "id": "q4-plan"},
		"action":                  map[string]any{"name": "can_read"},
		"context":                 map[string]any{"project": "renewal"},
	}
}

func (f *fixture) submission(t *testing.T, claims map[string]any) map[string]any {
	return map[string]any{
		"subject":  map[string]any{"type": "user", "id": "alice", "properties": map[string]any{"act": map[string]any{"sub": "agent-7"}}},
		"resource": map[string]any{"type": "document", "id": "q4-plan"},
		"action":   map[string]any{"name": "can_read"},
		"context":  map[string]any{"project": "renewal", "business_justification": "renewal review"},
		"denial": map[string]any{
			"expires_at":    claims["denial_expires_at"],
			"evaluation_id": "eval_1",
			"binding_token": signJWT(t, f.pdpKey, claims),
			"template":      "manager_approval",
		},
	}
}

func (f *fixture) do(t *testing.T, method, path, token string, body any, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, req)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	return out
}

func problemType(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); ct != problemContentType {
		t.Fatalf("expected a problem document, got %s: %s", ct, w.Body.String())
	}
	typ, _ := decode(t, w)["type"].(string)
	return typ
}

func TestSubmitPending(t *testing.T) {
	f := newFixture(t)
	w := f.do(t, http.MethodPost, RequestsPath, f.callerToken(t, "agent-7"), f.submission(t, bindingClaims()))
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}
	task := decode(t, w)["task"].(map[string]any)
	id := task["id"].(string)
	if !strings.HasPrefix(id, "arq_") || task["status"] != "pending" || task["status_endpoint"] != baseURL+RequestsPath+"/"+id {
		t.Fatalf("task handle: %v", task)
	}
	if w.Header().Get("Location") != task["status_endpoint"] {
		t.Fatalf("Location %q", w.Header().Get("Location"))
	}
	progress := task["progress"].(map[string]any)
	if progress["step_name"] != "manager_approval" || progress["current_step"] != float64(1) {
		t.Fatalf("progress: %v", progress)
	}
	if _, has := progress["awaiting"]; has {
		t.Fatal("approvers disclosed without disclose_approvers")
	}
	if task["links"].(map[string]any)["cancel"] != baseURL+RequestsPath+"/"+id+"/cancel" {
		t.Fatalf("links: %v", task["links"])
	}
	stored, err := f.store.GetTask(context.Background(), id)
	if err != nil || stored.RequesterSub != "agent-7" || stored.EvaluationID != "eval_1" {
		t.Fatalf("stored: %+v %v", stored, err)
	}
	if len(f.audit.events) != 1 || f.audit.events[0] != "submitted" {
		t.Fatalf("audit: %v", f.audit.events)
	}
}

func TestSubmitAutoApprove(t *testing.T) {
	f := newFixture(t)
	f.rules["ars_workflow"] = func(map[string]any) any {
		return map[string]any{"auto": "approve", "approved_until": now.Add(4 * time.Hour).Format(time.RFC3339)}
	}
	w := f.do(t, http.MethodPost, RequestsPath, f.callerToken(t, "agent-7"), f.submission(t, bindingClaims()))
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	body := decode(t, w)
	if body["task"].(map[string]any)["status"] != "approved" {
		t.Fatalf("task: %v", body["task"])
	}
	approval := body["result"].(map[string]any)["approval"].(map[string]any)
	if body["result"].(map[string]any)["mode"] != "reevaluate" || approval["approved_until"] != now.Add(4*time.Hour).Format(time.RFC3339) {
		t.Fatalf("result: %v", body["result"])
	}
	claims, err := testCrypto{key: f.pdpKey}.VerifyBindingToken(approval["state"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if claims["approval_id"] != approval["id"] || claims["aud"] != baseURL {
		t.Fatalf("state claims: %v", claims)
	}
	if props, ok := claims["subject"].(map[string]any)["properties"].(map[string]any); ok {
		if _, has := props["act"]; has {
			t.Fatal("approval binds the actor")
		}
	}
	a, err := f.store.GetApproval(context.Background(), approval["id"].(string))
	if err != nil || a.Context["project"] != "renewal" || a.BindingContextMembers[0] != "project" {
		t.Fatalf("stored approval: %+v %v", a, err)
	}
	if strings.Join(f.audit.events, ",") != "submitted,approved" {
		t.Fatalf("audit: %v", f.audit.events)
	}
}

func TestSubmitAutoDeny(t *testing.T) {
	f := newFixture(t)
	f.rules["ars_workflow"] = func(map[string]any) any { return map[string]any{"auto": "deny"} }
	w := f.do(t, http.MethodPost, RequestsPath, f.callerToken(t, "agent-7"), f.submission(t, bindingClaims()))
	body := decode(t, w)
	if w.Code != http.StatusCreated || body["task"].(map[string]any)["status"] != "denied" || body["result"] != nil {
		t.Fatalf("got %d %v", w.Code, body)
	}
}

func TestSubmitApprovedUntilCapped(t *testing.T) {
	f := newFixture(t)
	f.rules["ars_workflow"] = func(map[string]any) any {
		return map[string]any{"auto": "approve", "approved_until": now.Add(365 * 24 * time.Hour).Format(time.RFC3339)}
	}
	w := f.do(t, http.MethodPost, RequestsPath, f.callerToken(t, "agent-7"), f.submission(t, bindingClaims()))
	approval := decode(t, w)["result"].(map[string]any)["approval"].(map[string]any)
	if approval["approved_until"] != now.Add(30*24*time.Hour).Format(time.RFC3339) {
		t.Fatalf("approved_until not capped: %v", approval["approved_until"])
	}
}

func TestSubmitIdempotency(t *testing.T) {
	f := newFixture(t)
	tok := f.callerToken(t, "agent-7")
	body := f.submission(t, bindingClaims())
	first := f.do(t, http.MethodPost, RequestsPath, tok, body, "Idempotency-Key", "k1")
	retry := f.do(t, http.MethodPost, RequestsPath, tok, body, "Idempotency-Key", "k1")
	if first.Code != http.StatusAccepted || retry.Code != http.StatusAccepted {
		t.Fatalf("codes %d %d: %s", first.Code, retry.Code, retry.Body.String())
	}
	if decode(t, first)["task"].(map[string]any)["id"] != decode(t, retry)["task"].(map[string]any)["id"] {
		t.Fatal("an idempotent retry produced a second task")
	}
	if len(f.audit.events) != 1 {
		t.Fatalf("a retry must not be audited again: %v", f.audit.events)
	}
	body["context"].(map[string]any)["business_justification"] = "changed"
	if w := f.do(t, http.MethodPost, RequestsPath, tok, body, "Idempotency-Key", "k1"); w.Code != http.StatusConflict || problemType(t, w) != ProblemDuplicate {
		t.Fatalf("expected duplicate_request, got %d %s", w.Code, w.Body.String())
	}
}

func TestSubmitRejects(t *testing.T) {
	f := newFixture(t)
	tok := f.callerToken(t, "agent-7")
	withClaims := func(edit func(map[string]any)) map[string]any {
		c := bindingClaims()
		edit(c)
		return f.submission(t, c)
	}
	withBody := func(edit func(map[string]any)) map[string]any {
		b := f.submission(t, bindingClaims())
		edit(b)
		return b
	}
	stranger := newKey(t, "pdp-1")
	cases := map[string]struct {
		body   map[string]any
		status int
		typ    string
	}{
		"no denial":        {withBody(func(b map[string]any) { delete(b, "denial") }), 400, ProblemNotRequestable},
		"no binding token": {withBody(func(b map[string]any) { delete(b["denial"].(map[string]any), "binding_token") }), 400, ProblemInvalidBinding},
		"forged token": {withBody(func(b map[string]any) {
			b["denial"].(map[string]any)["binding_token"] = signJWT(t, stranger, bindingClaims())
		}), 400, ProblemInvalidBinding},
		"other issuer":         {withClaims(func(c map[string]any) { c["iss"] = "https://other-pdp.example" }), 400, ProblemInvalidBinding},
		"other audience":       {withClaims(func(c map[string]any) { c["aud"] = "https://other-ars.example" }), 400, ProblemInvalidBinding},
		"resource substituted": {withBody(func(b map[string]any) { b["resource"] = map[string]any{"type": "document", "id": "q3-plan"} }), 400, ProblemInvalidBinding},
		"context substituted":  {withBody(func(b map[string]any) { b["context"].(map[string]any)["project"] = "other" }), 400, ProblemInvalidBinding},
		"echoed expiry edited": {withBody(func(b map[string]any) {
			b["denial"].(map[string]any)["expires_at"] = now.Add(time.Hour).Format(time.RFC3339)
		}), 400, ProblemInvalidBinding},
		"evaluation id edited": {withBody(func(b map[string]any) { b["denial"].(map[string]any)["evaluation_id"] = "eval_2" }), 400, ProblemInvalidBinding},
		"expired denial": {withClaims(func(c map[string]any) {
			c["exp"] = float64(now.Add(-time.Hour).Unix())
			c["denial_expires_at"] = now.Add(-time.Hour).Format(time.RFC3339)
		}), 410, ProblemExpiredDenial},
		"bulk items":  {withBody(func(b map[string]any) { b["items"] = []any{} }), 400, problemGeneric},
		"bad subject": {withBody(func(b map[string]any) { b["subject"] = map[string]any{"type": "user"} }), 400, problemGeneric},
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

// A denial of a subject with an actor, submitted by a PEP that moved the
// actor to client.actor and dropped the emptied properties, still binds.
func TestSubmitActorNormalizedToClient(t *testing.T) {
	f := newFixture(t)
	claims := bindingClaims()
	claims["subject"] = map[string]any{"type": "user", "id": "alice", "properties": map[string]any{"act": map[string]any{"sub": "agent-7"}}}
	body := f.submission(t, claims)
	body["subject"] = map[string]any{"type": "user", "id": "alice"}
	body["client"] = map[string]any{"actor": map[string]any{"id": "agent-7"}}
	if w := f.do(t, http.MethodPost, RequestsPath, f.callerToken(t, "agent-7"), body); w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}
}

func TestWithoutActor(t *testing.T) {
	cases := []struct{ in, want map[string]any }{
		{map[string]any{"id": "a", "properties": map[string]any{"act": 1, "dept": "x"}}, map[string]any{"id": "a", "properties": map[string]any{"dept": "x"}}},
		{map[string]any{"id": "a", "properties": map[string]any{"act": 1}}, map[string]any{"id": "a"}},
		// An explicitly empty properties object, with no actor, is kept.
		{map[string]any{"id": "a", "properties": map[string]any{}}, map[string]any{"id": "a", "properties": map[string]any{}}},
	}
	for _, c := range cases {
		if got := WithoutActor(c.in); !SameBinding(got, c.want) {
			t.Errorf("WithoutActor(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSubmitReplayRejected(t *testing.T) {
	f := newFixture(t)
	tok := f.callerToken(t, "agent-7")
	body := f.submission(t, bindingClaims())
	if w := f.do(t, http.MethodPost, RequestsPath, tok, body); w.Code != http.StatusAccepted {
		t.Fatalf("first: %d", w.Code)
	}
	if w := f.do(t, http.MethodPost, RequestsPath, tok, body); w.Code != http.StatusBadRequest || problemType(t, w) != ProblemInvalidBinding {
		t.Fatalf("replay: %d %s", w.Code, w.Body.String())
	}
}

func TestSubmitAuthAndPolicy(t *testing.T) {
	f := newFixture(t)
	body := f.submission(t, bindingClaims())
	if w := f.do(t, http.MethodPost, RequestsPath, "", body); w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("no token: %d", w.Code)
	}
	if w := f.do(t, http.MethodPost, RequestsPath, f.approverToken(t, "agent-7"), body); w.Code != http.StatusUnauthorized {
		t.Fatalf("approver-audience token on the caller API: %d", w.Code)
	}
	f.rules["ars_caller"] = func(map[string]any) any { return false }
	if w := f.do(t, http.MethodPost, RequestsPath, f.callerToken(t, "agent-7"), body); w.Code != http.StatusForbidden {
		t.Fatalf("caller rule false: %d", w.Code)
	}
	f.rules["ars_caller"] = func(map[string]any) any { return true }
	f.rules["ars_workflow"] = func(map[string]any) any { return map[string]any{"steps": "nope"} }
	if w := f.do(t, http.MethodPost, RequestsPath, f.callerToken(t, "agent-7"), body); w.Code != http.StatusInternalServerError {
		t.Fatalf("malformed workflow: %d", w.Code)
	}
}

func TestCallerRuleSeesNoUnverifiedActor(t *testing.T) {
	f := newFixture(t)
	var seen map[string]any
	f.rules["ars_caller"] = func(in map[string]any) any { seen = in; return true }
	body := f.submission(t, bindingClaims())
	body["client"] = map[string]any{"id": "app", "actor": map[string]any{"id": "agent"}, "source": map[string]any{"session_id": "s"}}
	f.do(t, http.MethodPost, RequestsPath, f.callerToken(t, "agent-7"), body)
	client := seen["submission"].(map[string]any)["client"].(map[string]any)
	if client["id"] != "app" || client["actor"] != nil || client["source"] != nil {
		t.Fatalf("rule saw %v", client)
	}
}

func TestStatusAndCancel(t *testing.T) {
	f := newFixture(t)
	tok := f.callerToken(t, "agent-7")
	w := f.do(t, http.MethodPost, RequestsPath, tok, f.submission(t, bindingClaims()))
	id := decode(t, w)["task"].(map[string]any)["id"].(string)
	path := RequestsPath + "/" + id

	if w := f.do(t, http.MethodGet, path, tok, nil); w.Code != http.StatusOK || decode(t, w)["task"].(map[string]any)["status"] != "pending" {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	// Another caller is not told the task exists.
	if w := f.do(t, http.MethodGet, path, f.callerToken(t, "intruder"), nil); w.Code != http.StatusNotFound || problemType(t, w) != ProblemUnknownTask {
		t.Fatalf("other caller: %d", w.Code)
	}
	if w := f.do(t, http.MethodGet, RequestsPath+"/arq_missing", tok, nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown: %d", w.Code)
	}
	if w := f.do(t, http.MethodPost, path+"/cancel", f.callerToken(t, "intruder"), nil); w.Code != http.StatusNotFound {
		t.Fatalf("other caller cancel: %d", w.Code)
	}
	w = f.do(t, http.MethodPost, path+"/cancel", tok, map[string]any{"reason": "no_longer_needed"})
	if w.Code != http.StatusOK || decode(t, w)["task"].(map[string]any)["status"] != "cancelled" {
		t.Fatalf("cancel: %d %s", w.Code, w.Body.String())
	}
	if w := f.do(t, http.MethodDelete, path+"/cancel", tok, nil); w.Code != http.StatusConflict || problemType(t, w) != ProblemInvalidState {
		t.Fatalf("second cancel: %d", w.Code)
	}
	// Past retention a terminal task is gone.
	f.svc.d.Now = func() time.Time { return now.Add(100 * time.Hour) }
	if w := f.do(t, http.MethodGet, path, tok, nil); w.Code != http.StatusGone || problemType(t, w) != ProblemTaskExpired {
		t.Fatalf("after retention: %d", w.Code)
	}
}

func TestTaskHandleDisclosesApproversWhenAllowed(t *testing.T) {
	f := newFixture(t)
	f.rules["ars_workflow"] = func(map[string]any) any {
		return map[string]any{"steps": []any{map[string]any{
			"name": "owner_review", "disclose_approvers": true,
			"approvers": []any{map[string]any{"type": "user", "id": "owner"}},
		}}}
	}
	f.svc.d.Links = Links{Ticket: "https://ui.example.com/requests/{id}"}
	w := f.do(t, http.MethodPost, RequestsPath, f.callerToken(t, "agent-7"), f.submission(t, bindingClaims()))
	task := decode(t, w)["task"].(map[string]any)
	if got := task["progress"].(map[string]any)["awaiting"]; len(got.([]any)) != 1 || got.([]any)[0] != "owner" {
		t.Fatalf("awaiting: %v", got)
	}
	if task["links"].(map[string]any)["ticket"] != "https://ui.example.com/requests/"+task["id"].(string) {
		t.Fatalf("ticket link: %v", task["links"])
	}
}
