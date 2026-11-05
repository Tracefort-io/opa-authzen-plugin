package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// --- PDP metadata base URL (Section 9.1.1) ---------------------------------

func wellKnownPDP(t *testing.T, p *AuthZenPlugin, host string, headers map[string]string) pdpMetadata {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/authzen-configuration", nil)
	req.Host = host
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	p.handleWellKnown(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var md pdpMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &md); err != nil {
		t.Fatal(err)
	}
	return md
}

func TestWellKnownPrefersForwardedHostOverRequestHost(t *testing.T) {
	p := testPlugin(t, `package authzen`)
	md := wellKnownPDP(t, p, "opa.internal:8181", map[string]string{
		"X-Forwarded-Host":  "pdp.example.com",
		"X-Forwarded-Proto": "https",
	})
	if md.PolicyDecisionPoint != "https://pdp.example.com" {
		t.Fatalf("expected the forwarded host, got %s", md.PolicyDecisionPoint)
	}
	if md.AccessEvaluationEndpoint != "https://pdp.example.com/access/v1/evaluation" {
		t.Fatalf("unexpected evaluation endpoint %s", md.AccessEvaluationEndpoint)
	}
}

func TestWellKnownUsesFirstForwardedValue(t *testing.T) {
	p := testPlugin(t, `package authzen`)
	md := wellKnownPDP(t, p, "opa.internal:8181", map[string]string{
		"X-Forwarded-Host":  "pdp.example.com, edge.internal",
		"X-Forwarded-Proto": "HTTPS, http",
	})
	if md.PolicyDecisionPoint != "https://pdp.example.com" {
		t.Fatalf("expected the client-facing values, got %s", md.PolicyDecisionPoint)
	}
}

func TestWellKnownIgnoresMalformedForwardedHost(t *testing.T) {
	p := testPlugin(t, `package authzen`)
	for _, bad := range []string{"evil.example/path", "user@evil.example", "a b", "evil.example?x"} {
		md := wellKnownPDP(t, p, "pdp.example.com", map[string]string{"X-Forwarded-Host": bad})
		if md.PolicyDecisionPoint != "http://pdp.example.com" {
			t.Fatalf("%q: expected fallback to the request host, got %s", bad, md.PolicyDecisionPoint)
		}
	}
}

func TestWellKnownBaseURLOverridesHeaders(t *testing.T) {
	cfg, err := Validate(nil, []byte(`{"base_url": "https://pdp.example.com/authz/"}`))
	if err != nil {
		t.Fatal(err)
	}
	p := testPlugin(t, `package authzen`)
	p.cfg = *cfg
	md := wellKnownPDP(t, p, "opa.internal:8181", map[string]string{"X-Forwarded-Host": "evil.example"})
	if md.PolicyDecisionPoint != "https://pdp.example.com/authz" {
		t.Fatalf("expected the pinned base_url, got %s", md.PolicyDecisionPoint)
	}
	if md.AccessEvaluationsEndpoint != "https://pdp.example.com/authz/access/v1/evaluations" {
		t.Fatalf("unexpected evaluations endpoint %s", md.AccessEvaluationsEndpoint)
	}
}

func TestValidateRejectsBadBaseURL(t *testing.T) {
	for _, bad := range []string{"pdp.example.com", "ftp://pdp.example.com", "https://pdp.example.com/?a=b", "https://pdp.example.com/#f", "https://"} {
		if _, err := Validate(nil, []byte(fmt.Sprintf(`{"base_url": %q}`, bad))); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

// --- Obligations Profile: obligation shape ---------------------------------

const obligationIssuingModule = `
	package authzen
	default allow = false
	allow if input.subject.id == "alice"
	ctx := {"obligations": input.context.issue}
`

func obligationPlugin(t *testing.T, advertised ...string) *AuthZenPlugin {
	t.Helper()
	p := testPlugin(t, obligationIssuingModule)
	p.cfg.DecisionContext = "ctx"
	p.cfg.SupportedObligations = advertised
	return p
}

func issueBody(obligations string) string {
	return fmt.Sprintf(`{
		"subject": {"type": "user", "id": "alice"},
		"resource": {"type": "doc", "id": "1"},
		"action": {"name": "read"},
		"context": {"issue": %s}
	}`, obligations)
}

func TestObligationsWellFormedPassThrough(t *testing.T) {
	p := obligationPlugin(t, "step-up", "notification", "session_termination", "custom")
	body := issueBody(`[
		{"id": "o1", "type": "step-up", "properties": {"acr_value": "urn:example:loa:3", "amr_values": ["mfa"]}},
		{"id": "o2", "type": "notification", "properties": {"to": ["owner@example.com"], "body": "accessed", "topic": "t"}},
		{"id": "o3", "type": "session_termination", "properties": {"subject": "alice"}},
		{"id": "o4", "type": "custom", "properties": {"vendor": "x", "anything": [1, 2]}}
	]`)
	w := postEvaluation(p, body)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"o4"`) {
		t.Fatalf("obligations missing from response: %s", w.Body.String())
	}
}

func TestObligationsMalformedFailClosed(t *testing.T) {
	p := obligationPlugin(t, "step-up", "notification")
	cases := map[string]string{
		"not an array":         `{"id": "o1"}`,
		"missing id":           `[{"type": "notification", "properties": {"to": ["a"], "body": "b"}}]`,
		"duplicate id":         `[{"id": "o1", "type": "step-up", "properties": {"acr_value": "x"}}, {"id": "o1", "type": "step-up", "properties": {"acr_value": "y"}}]`,
		"unadvertised type":    `[{"id": "o1", "type": "session_termination", "properties": {"subject": "a"}}]`,
		"missing properties":   `[{"id": "o1", "type": "step-up"}]`,
		"step-up no acr":       `[{"id": "o1", "type": "step-up", "properties": {}}]`,
		"step-up bad amr":      `[{"id": "o1", "type": "step-up", "properties": {"acr_value": "x", "amr_values": "mfa"}}]`,
		"notification no to":   `[{"id": "o1", "type": "notification", "properties": {"body": "b"}}]`,
		"notification empty":   `[{"id": "o1", "type": "notification", "properties": {"to": [], "body": "b"}}]`,
		"notification dup to":  `[{"id": "o1", "type": "notification", "properties": {"to": ["a", "a"], "body": "b"}}]`,
		"notification no body": `[{"id": "o1", "type": "notification", "properties": {"to": ["a"]}}]`,
		"legacy shape":         `[{"id": "o1", "type": "notification", "properties": {"recipient": "a", "event": "e"}}]`,
	}
	for name, obligations := range cases {
		t.Run(name, func(t *testing.T) {
			w := postEvaluation(p, issueBody(obligations))
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestObligationsUncheckedWhenProfileUnconfigured(t *testing.T) {
	p := obligationPlugin(t)
	w := postEvaluation(p, issueBody(`[{"anything": true}]`))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 without supported_obligations, got %d: %s", w.Code, w.Body.String())
	}
}

const searchObligationModule = `
	package authzen
	resource_search contains {"type": "doc", "id": "1"}
	resource_search contains {"type": "doc", "id": "2", "obligations": input.context.issue}
`

func TestSearchResultObligationsChecked(t *testing.T) {
	p := testSearchPlugin(t, searchObligationModule)
	p.cfg.SupportedObligations = []string{"step-up"}
	body := func(issue string) string {
		return fmt.Sprintf(`{"subject": {"type": "user", "id": "alice"}, "action": {"name": "read"},
			"resource": {"type": "doc"}, "context": {"issue": %s}}`, issue)
	}

	w := doSearch(t, p, "/access/v1/search/resource", body(`[{"id": "s1", "type": "step-up", "properties": {"acr_value": "urn:example:loa:3"}}]`))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"obligations":[{"id":"s1"`) {
		t.Fatalf("per-result obligations not returned: %s", w.Body.String())
	}

	w = doSearch(t, p, "/access/v1/search/resource", body(`[{"id": "s1", "type": "step-up", "properties": {}}]`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for a malformed per-result obligation, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Access Request and Approval Profile -----------------------------------

const pdpID = "https://pdp.example.com"

// testKey writes an ES256 key pair. It returns the private JWK file and a
// JWK Set file holding the public half.
func testKey(t *testing.T, dir, kid string) (privFile, pubSetFile string, priv jwk.Key) {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv, err = jwk.Import(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := priv.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	if err := priv.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatal(err)
	}
	privFile = filepath.Join(dir, kid+".jwk")
	pubSetFile = filepath.Join(dir, kid+"-jwks.json")
	writeJSONFile(t, privFile, priv)
	writeJSONFile(t, pubSetFile, set)
	return privFile, pubSetFile, priv
}

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

const requestableModule = `
	package authzen
	default allow = false
	allow if input.subject.id == "alice"
	allow if input.context.approval.verified
	ctx := object.union(
		{"access_request": input.context.hint},
		{k: v | some k, v in input.context.extra},
	) if input.context.hint
	ctx := {"approval_seen": input.context.approval} if {
		not input.context.hint
		input.context.approval
	}
	ctx := input.context.extra if {
		not input.context.hint
		not input.context.approval
	}
`

type arapFixture struct {
	p        *AuthZenPlugin
	pdpPub   string
	arsPriv  jwk.Key
	arsIssue string
}

func newARAPFixture(t *testing.T, extra string) arapFixture {
	t.Helper()
	dir := t.TempDir()
	pdpPriv, pdpPub, _ := testKey(t, dir, "pdp-1")
	_, arsPub, arsPriv := testKey(t, dir, "ars-1")
	conf := fmt.Sprintf(`{
		"decision_context": "ctx",
		"base_url": %q,
		"access_request_endpoint": "https://requests.example.com/access/v1/requests",
		"access_request": {
			"signing_key_file": %q,
			"audience": "https://requests.example.com",
			"binding_context_members": ["project"],
			"approval_issuers": [{"issuer": "https://requests.example.com", "jwks_file": %q}]
			%s
		}
	}`, pdpID, pdpPriv, arsPub, extra)
	cfg, err := Validate(nil, []byte(conf))
	if err != nil {
		t.Fatal(err)
	}
	p := testPlugin(t, requestableModule)
	p.cfg = *cfg
	p.now = func() time.Time { return time.Date(2026, 4, 30, 20, 15, 0, 0, time.UTC) }
	return arapFixture{p: p, pdpPub: pdpPub, arsPriv: arsPriv, arsIssue: "https://requests.example.com"}
}

func decisionContextOf(t *testing.T, w *httptest.ResponseRecorder) (bool, map[string]any) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Decision bool           `json:"decision"`
		Context  map[string]any `json:"context"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Decision, resp.Context
}

func hintBody(subject, hint, extra string) string {
	if extra == "" {
		extra = "{}"
	}
	return fmt.Sprintf(`{
		"subject": {"type": "user", "id": %q, "properties": {"act": {"sub": "agent-7"}, "dept": "sales"}},
		"resource": {"type": "document", "id": "q4-plan"},
		"action": {"name": "can_read"},
		"context": {"project": "renewal", "time": "now", "hint": %s, "extra": %s}
	}`, subject, hint, extra)
}

func TestRequestableDenialIsCompletedAndSigned(t *testing.T) {
	f := newARAPFixture(t, "")
	decision, ctx := decisionContextOf(t, postEvaluation(f.p, hintBody("bob", `{"template": "manager_approval"}`, "")))
	if decision {
		t.Fatal("expected a denial")
	}
	ar, ok := ctx["access_request"].(map[string]any)
	if !ok {
		t.Fatalf("access_request missing: %v", ctx)
	}
	if ar["expires_at"] != "2026-04-30T20:25:00Z" {
		t.Fatalf("expected the default 10m expiry, got %v", ar["expires_at"])
	}
	evalID, _ := ctx["evaluation_id"].(string)
	if !strings.HasPrefix(evalID, "eval_") {
		t.Fatalf("expected a generated evaluation_id, got %v", ctx["evaluation_id"])
	}
	if ctx["evaluated_at"] != "2026-04-30T20:15:00Z" {
		t.Fatalf("unexpected evaluated_at %v", ctx["evaluated_at"])
	}
	token, _ := ar["binding_token"].(string)
	if token == "" {
		t.Fatalf("expected a binding_token: %v", ar)
	}

	// The token verifies against the key the PDP serves at its jwks_uri.
	w := httptest.NewRecorder()
	f.p.handleJWKS(w, httptest.NewRequest(http.MethodGet, jwksPath, nil))
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/jwk-set+json" {
		t.Fatalf("jwks: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	served, err := jwk.Parse(w.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if served.Len() != 2 {
		t.Fatalf("expected the PDP key and the trusted ARS key, got %d", served.Len())
	}
	for i := range served.Len() {
		k, _ := served.Key(i)
		if private, _ := jwk.IsPrivateKey(k); private {
			t.Fatal("served JWK Set leaks a private key")
		}
	}
	payload, err := jws.Verify([]byte(token), jws.WithKeySet(served))
	if err != nil {
		t.Fatalf("binding_token does not verify against the served JWK Set: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"iss":               pdpID,
		"aud":               "https://requests.example.com",
		"evaluation_id":     evalID,
		"denial_expires_at": "2026-04-30T20:25:00Z",
	}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("claim %s = %v, want %v", k, claims[k], v)
		}
	}
	if claims["exp"].(float64) != float64(time.Date(2026, 4, 30, 20, 25, 0, 0, time.UTC).Unix()) {
		t.Errorf("exp does not match expires_at: %v", claims["exp"])
	}
	subject := claims["subject"].(map[string]any)
	if _, has := subject["properties"].(map[string]any)["act"]; has {
		t.Error("subject.properties.act must be excluded from the binding")
	}
	if got := claims["context"].(map[string]any); len(got) != 1 || got["project"] != "renewal" {
		t.Errorf("expected only the authorization-relevant context member, got %v", got)
	}
	if fmt.Sprint(claims["binding_context_members"]) != "[project]" {
		t.Errorf("unexpected binding_context_members %v", claims["binding_context_members"])
	}
}

func TestRequestableDenialKeepsPolicyValues(t *testing.T) {
	f := newARAPFixture(t, "")
	_, ctx := decisionContextOf(t, postEvaluation(f.p, hintBody("bob",
		`{"expires_at": "2026-04-30T21:00:00Z", "binding_token": "policy-made"}`,
		`{"evaluation_id": "eval_fixed", "evaluated_at": "2026-04-30T20:14:00Z"}`)))
	ar := ctx["access_request"].(map[string]any)
	if ar["expires_at"] != "2026-04-30T21:00:00Z" || ar["binding_token"] != "policy-made" {
		t.Fatalf("policy-supplied values overwritten: %v", ar)
	}
	if ctx["evaluation_id"] != "eval_fixed" || ctx["evaluated_at"] != "2026-04-30T20:14:00Z" {
		t.Fatalf("policy-supplied ids overwritten: %v", ctx)
	}
}

func TestRequestableDenialDroppedOnPermit(t *testing.T) {
	f := newARAPFixture(t, "")
	decision, ctx := decisionContextOf(t, postEvaluation(f.p, hintBody("alice", `{}`, "")))
	if !decision {
		t.Fatal("expected a permit")
	}
	if _, has := ctx["access_request"]; has {
		t.Fatalf("access_request must not appear on a permit: %v", ctx)
	}
}

func TestRequestableDenialDroppedWithoutEndpoint(t *testing.T) {
	p := testPlugin(t, requestableModule)
	p.cfg.DecisionContext = "ctx"
	_, ctx := decisionContextOf(t, postEvaluation(p, hintBody("bob", `{"expires_at": "2026-04-30T21:00:00Z"}`, "")))
	if _, has := ctx["access_request"]; has {
		t.Fatalf("access_request must be dropped when no endpoint is available: %v", ctx)
	}

	// A hint naming its own endpoint stands without one configured.
	_, ctx = decisionContextOf(t, postEvaluation(p, hintBody("bob", `{"endpoint": "https://requests.example.com/r"}`, "")))
	if _, has := ctx["access_request"]; !has {
		t.Fatalf("expected the hint with its own endpoint to be kept: %v", ctx)
	}
}

func TestRequestableDenialRejectsBadMembers(t *testing.T) {
	f := newARAPFixture(t, "")
	// hint "false" emits only the extra members, as a re-evaluation denial
	// would.
	cases := map[string][2]string{
		"hint not object":         {`"yes"`, ""},
		"expires_at not RFC 3339": {`{"expires_at": "tomorrow"}`, ""},
		"expires_at in the past":  {`{"expires_at": "2026-04-30T20:00:00Z"}`, ""},
		"endpoint not https":      {`{"endpoint": "http://requests.example.com/r"}`, ""},
		"evaluation_id not text":  {`{}`, `{"evaluation_id": 7}`},
		"request without hint":    {`false`, `{"next_action": "request"}`},
		"next_action not text":    {`false`, `{"next_action": 1}`},
		"retry_after negative":    {`false`, `{"next_action": "retry", "retry_after": -1}`},
		"retry_after fractional":  {`false`, `{"next_action": "retry", "retry_after": 1.5}`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			w := postEvaluation(f.p, hintBody("bob", c[0], c[1]))
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
			}
		})
	}

	// The well-formed re-evaluation denial members pass.
	_, ctx := decisionContextOf(t, postEvaluation(f.p, hintBody("bob", `false`, `{"next_action": "retry", "retry_after": 30, "reason": "grant_pending"}`)))
	if ctx["next_action"] != "retry" {
		t.Fatalf("unexpected context %v", ctx)
	}
}

func TestRequestableDenialFinalizedPerBatchItem(t *testing.T) {
	f := newARAPFixture(t, "")
	body := `{
		"resource": {"type": "document", "id": "q4-plan"},
		"action": {"name": "can_read"},
		"context": {"project": "renewal", "hint": {}},
		"evaluations": [
			{"subject": {"type": "user", "id": "alice"}},
			{"subject": {"type": "user", "id": "bob"}}
		]
	}`
	resp := decodeBatchResp(t, postEvaluations(f.p, body))
	if len(resp.Evaluations) != 2 {
		t.Fatalf("expected 2 results, got %d", len(resp.Evaluations))
	}
	if strings.Contains(string(resp.Evaluations[0].Context), "access_request") {
		t.Fatalf("permit carries access_request: %s", resp.Evaluations[0].Context)
	}
	if !strings.Contains(string(resp.Evaluations[1].Context), "binding_token") {
		t.Fatalf("denial lacks binding_token: %s", resp.Evaluations[1].Context)
	}
}

func TestJWKSNotFoundWithoutKeys(t *testing.T) {
	p := testPlugin(t, `package authzen`)
	w := httptest.NewRecorder()
	p.handleJWKS(w, httptest.NewRequest(http.MethodGet, jwksPath, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestWellKnownAdvertisesServedJWKS(t *testing.T) {
	f := newARAPFixture(t, "")
	md := wellKnownPDP(t, f.p, "pdp.example.com", nil)
	if md.JWKSURI != pdpID+jwksPath {
		t.Fatalf("expected the served JWK Set to be advertised, got %q", md.JWKSURI)
	}
}

// --- Approval verification at re-evaluation --------------------------------

func signApproval(t *testing.T, key jwk.Key, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	hdr := jws.NewHeaders()
	_ = hdr.Set(jws.KeyIDKey, "ars-1")
	out, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func approvalClaims(f arapFixture) map[string]any {
	return map[string]any{
		"iss":                     f.arsIssue,
		"aud":                     pdpID,
		"approval_id":             "apr_1",
		"task_id":                 "arq_1",
		"approved_at":             "2026-04-30T20:10:00Z",
		"approved_until":          "2026-05-01T00:00:00Z",
		"subject":                 map[string]any{"type": "user", "id": "bob", "properties": map[string]any{"dept": "sales"}},
		"resource":                map[string]any{"type": "document", "id": "q4-plan"},
		"action":                  map[string]any{"name": "can_read"},
		"binding_context_members": []string{"project"},
		"context":                 map[string]any{"project": "renewal"},
	}
}

func reevaluationBody(approval string) string {
	return fmt.Sprintf(`{
		"subject": {"type": "user", "id": "bob", "properties": {"act": {"sub": "agent-9"}, "dept": "sales"}},
		"resource": {"type": "document", "id": "q4-plan"},
		"action": {"name": "can_read"},
		"context": {"project": "renewal", "time": "later", "approval": %s}
	}`, approval)
}

func TestApprovalVerifiedReplacesPEPValues(t *testing.T) {
	f := newARAPFixture(t, "")
	state := signApproval(t, f.arsPriv, approvalClaims(f))
	// The PEP's own approved_until and verified are ignored.
	approval := fmt.Sprintf(`{"id": "apr_1", "approved_until": "2099-01-01T00:00:00Z", "verified": true, "state": %q}`, state)
	decision, ctx := decisionContextOf(t, postEvaluation(f.p, reevaluationBody(approval)))
	if !decision {
		t.Fatalf("expected the verified approval to permit: %v", ctx)
	}
	seen := ctx["approval_seen"].(map[string]any)
	want := map[string]any{
		"id": "apr_1", "verified": true, "issuer": f.arsIssue,
		"approved_until": "2026-05-01T00:00:00Z", "approved_at": "2026-04-30T20:10:00Z", "task_id": "arq_1",
	}
	if len(seen) != len(want) {
		t.Fatalf("policy saw %v, want %v", seen, want)
	}
	for k, v := range want {
		if seen[k] != v {
			t.Fatalf("policy saw %s=%v, want %v", k, seen[k], v)
		}
	}
}

func TestApprovalNotAccepted(t *testing.T) {
	f := newARAPFixture(t, "")
	_, _, stranger := testKey(t, t.TempDir(), "ars-1")

	mutate := func(fn func(map[string]any)) string {
		c := approvalClaims(f)
		fn(c)
		return signApproval(t, f.arsPriv, c)
	}
	cases := map[string]struct {
		approval string
		reason   string
	}{
		"forged verified flag": {`{"id": "apr_1", "verified": true}`, reasonApprovalUnverifiable},
		"not an object":        {`"apr_1"`, reasonApprovalUnverifiable},
		"wrong signer": {fmt.Sprintf(`{"id": "apr_1", "state": %q}`, signApproval(t, stranger, approvalClaims(f))),
			reasonApprovalUnverifiable},
		"untrusted issuer": {fmt.Sprintf(`{"id": "apr_1", "state": %q}`, mutate(func(c map[string]any) { c["iss"] = "https://other.example" })),
			reasonApprovalUnverifiable},
		"wrong audience": {fmt.Sprintf(`{"id": "apr_1", "state": %q}`, mutate(func(c map[string]any) { c["aud"] = "https://other-pdp.example" })),
			reasonApprovalUnverifiable},
		"swapped id": {fmt.Sprintf(`{"id": "apr_2", "state": %q}`, mutate(func(map[string]any) {})),
			reasonApprovalUnverifiable},
		"expired": {fmt.Sprintf(`{"id": "apr_1", "state": %q}`, mutate(func(c map[string]any) { c["approved_until"] = "2026-04-30T20:00:00Z" })),
			reasonApprovalExpired},
		"other resource": {fmt.Sprintf(`{"id": "apr_1", "state": %q}`, mutate(func(c map[string]any) {
			c["resource"] = map[string]any{"type": "document", "id": "q3-plan"}
		})), reasonOutOfScope},
		"other context": {fmt.Sprintf(`{"id": "apr_1", "state": %q}`, mutate(func(c map[string]any) {
			c["context"] = map[string]any{"project": "other"}
		})), reasonOutOfScope},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			decision, ctx := decisionContextOf(t, postEvaluation(f.p, reevaluationBody(c.approval)))
			if decision {
				t.Fatalf("expected a denial: %v", ctx)
			}
			seen := ctx["approval_seen"].(map[string]any)
			if seen["verified"] != false || seen["reason"] != c.reason {
				t.Fatalf("policy saw %v, want verified=false reason=%s", seen, c.reason)
			}
		})
	}
}

func TestApprovalPassedThroughWithoutTrustedIssuers(t *testing.T) {
	p := testPlugin(t, requestableModule)
	p.cfg.DecisionContext = "ctx"
	_, ctx := decisionContextOf(t, postEvaluation(p, reevaluationBody(`{"id": "apr_1", "approved_until": "2026-05-01T00:00:00Z"}`)))
	seen := ctx["approval_seen"].(map[string]any)
	if seen["id"] != "apr_1" || seen["approved_until"] != "2026-05-01T00:00:00Z" {
		t.Fatalf("approval should reach the policy unchanged: %v", seen)
	}
}

func TestValidateAccessRequestConfig(t *testing.T) {
	dir := t.TempDir()
	priv, pubSet, _ := testKey(t, dir, "k1")
	_, pubSet2, _ := testKey(t, dir, "k2")
	cases := map[string]string{
		"signing without base_url":  fmt.Sprintf(`{"access_request": {"signing_key_file": %q, "audience": "a"}}`, priv),
		"signing without audience":  fmt.Sprintf(`{"base_url": %q, "access_request": {"signing_key_file": %q}}`, pdpID, priv),
		"public key for signing":    fmt.Sprintf(`{"base_url": %q, "access_request": {"signing_key_file": %q, "audience": "a"}}`, pdpID, pubSet),
		"missing key file":          fmt.Sprintf(`{"base_url": %q, "access_request": {"signing_key_file": %q, "audience": "a"}}`, pdpID, filepath.Join(dir, "nope")),
		"audience without key":      `{"access_request": {"audience": "a"}}`,
		"issuers without base_url":  fmt.Sprintf(`{"access_request": {"approval_issuers": [{"issuer": "i", "jwks_file": %q}]}}`, pubSet),
		"private key as issuer key": fmt.Sprintf(`{"base_url": %q, "access_request": {"approval_issuers": [{"issuer": "i", "jwks_file": %q}]}}`, pdpID, priv),
		"duplicate issuer":          fmt.Sprintf(`{"base_url": %q, "access_request": {"approval_issuers": [{"issuer": "i", "jwks_file": %q}, {"issuer": "i", "jwks_file": %q}]}}`, pdpID, pubSet, pubSet2),
		"duplicate kid across sets": fmt.Sprintf(`{"base_url": %q, "access_request": {"approval_issuers": [{"issuer": "i", "jwks_file": %q}, {"issuer": "j", "jwks_file": %q}]}}`, pdpID, pubSet, pubSet),
		"bad ttl":                   `{"access_request": {"denial_ttl": "soon"}}`,
		"non-positive ttl":          `{"access_request": {"denial_ttl": "0s"}}`,
		"machinery member bound":    `{"access_request": {"binding_context_members": ["approval"]}}`,
		"duplicate member":          `{"access_request": {"binding_context_members": ["a", "a"]}}`,
		"empty member":              `{"access_request": {"binding_context_members": [" "]}}`,
	}
	for name, conf := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Validate(nil, []byte(conf)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}

	// An operator-advertised jwks_uri is kept rather than replaced.
	cfg, err := Validate(nil, []byte(fmt.Sprintf(`{"base_url": %q, "jwks_uri": "https://keys.example.com/jwks",
		"access_request": {"signing_key_file": %q, "audience": "a"}}`, pdpID, priv)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.JWKSURI != "https://keys.example.com/jwks" {
		t.Fatalf("operator jwks_uri replaced: %q", cfg.JWKSURI)
	}
}

// --- Short-circuit batches keep the policy's decision context ---------------

func batchItemContext(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var ctx map[string]any
	if err := json.Unmarshal(raw, &ctx); err != nil {
		t.Fatalf("item context %s: %v", raw, err)
	}
	return ctx
}

func TestDenyOnFirstDenyKeepsRequestableDenial(t *testing.T) {
	f := newARAPFixture(t, "")
	body := `{
		"resource": {"type": "document", "id": "q4-plan"},
		"action": {"name": "can_read"},
		"context": {"project": "renewal", "hint": {"template": "manager_approval"},
		            "extra": {"reason": "approval_required"}},
		"options": {"evaluations_semantic": "deny_on_first_deny"},
		"evaluations": [
			{"subject": {"type": "user", "id": "alice"}},
			{"subject": {"type": "user", "id": "bob"}},
			{"subject": {"type": "user", "id": "carol"}}
		]
	}`
	resp := decodeBatchResp(t, postEvaluations(f.p, body))
	if len(resp.Evaluations) != 2 {
		t.Fatalf("expected the batch to stop at the second item, got %d results", len(resp.Evaluations))
	}
	stop := resp.Evaluations[1]
	if stop.Decision {
		t.Fatal("expected the stopping item to be a denial")
	}
	ctx := batchItemContext(t, stop.Context)
	if ctx["code"] != "200" {
		t.Errorf("expected the short-circuit code, got %v", ctx["code"])
	}
	if ctx["reason"] != "approval_required" {
		t.Errorf("expected the policy's reason to win, got %v", ctx["reason"])
	}
	ar, ok := ctx["access_request"].(map[string]any)
	if !ok {
		t.Fatalf("requestable denial lost on the stopping item: %s", stop.Context)
	}
	if ar["binding_token"] == nil || ctx["evaluation_id"] == nil {
		t.Fatalf("stopping item lacks denial-binding material: %s", stop.Context)
	}
}

func TestShortCircuitMarkerFillsMissingReason(t *testing.T) {
	p := testPlugin(t, `package authzen
		default allow = false
		ctx := {"note": "checked"}`)
	p.cfg.DecisionContext = "ctx"
	body := `{
		"subject": {"type": "user", "id": "bob"},
		"action": {"name": "read"},
		"options": {"evaluations_semantic": "deny_on_first_deny"},
		"evaluations": [{"resource": {"type": "doc", "id": "1"}}, {"resource": {"type": "doc", "id": "2"}}]
	}`
	resp := decodeBatchResp(t, postEvaluations(p, body))
	if len(resp.Evaluations) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp.Evaluations))
	}
	ctx := batchItemContext(t, resp.Evaluations[0].Context)
	if ctx["code"] != "200" || ctx["reason"] != "deny_on_first_deny" || ctx["note"] != "checked" {
		t.Fatalf("expected the marker merged with the policy context, got %v", ctx)
	}
}

func TestShortCircuitMarkerUnchangedWithoutDecisionContext(t *testing.T) {
	p := testPlugin(t, `package authzen
		default allow = false`)
	body := `{
		"subject": {"type": "user", "id": "bob"},
		"action": {"name": "read"},
		"options": {"evaluations_semantic": "deny_on_first_deny"},
		"evaluations": [{"resource": {"type": "doc", "id": "1"}}, {"resource": {"type": "doc", "id": "2"}}]
	}`
	resp := decodeBatchResp(t, postEvaluations(p, body))
	if len(resp.Evaluations) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp.Evaluations))
	}
	if got := string(resp.Evaluations[0].Context); got != `{"code":"200","reason":"deny_on_first_deny"}` {
		t.Fatalf("marker changed without a decision_context: %s", got)
	}
}

func TestPermitOnFirstPermitKeepsObligations(t *testing.T) {
	p := obligationPlugin(t, "step-up")
	body := `{
		"resource": {"type": "doc", "id": "1"},
		"action": {"name": "read"},
		"context": {"issue": [{"id": "o1", "type": "step-up", "properties": {"acr_value": "urn:example:loa:3"}}]},
		"options": {"evaluations_semantic": "permit_on_first_permit"},
		"evaluations": [
			{"subject": {"type": "user", "id": "bob"}},
			{"subject": {"type": "user", "id": "alice"}},
			{"subject": {"type": "user", "id": "carol"}}
		]
	}`
	resp := decodeBatchResp(t, postEvaluations(p, body))
	if len(resp.Evaluations) != 2 {
		t.Fatalf("expected the batch to stop at the second item, got %d results", len(resp.Evaluations))
	}
	stop := resp.Evaluations[1]
	if !stop.Decision {
		t.Fatal("expected the stopping item to be a permit")
	}
	ctx := batchItemContext(t, stop.Context)
	if ctx["code"] != "200" || ctx["reason"] != "permit_on_first_permit" {
		t.Fatalf("expected the short-circuit marker, got %v", ctx)
	}
	if _, ok := ctx["obligations"].([]any); !ok {
		t.Fatalf("obligations lost on the stopping permit: %s", stop.Context)
	}
}
