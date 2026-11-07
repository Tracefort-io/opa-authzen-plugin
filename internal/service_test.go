package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars"
	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// serviceModule is a deployment's policy: Alice may read; anyone else needs
// a manager's approval, after which a verified approval permits.
const serviceModule = `
	package authzen

	default allow := false

	allow if input.subject.id == "alice"

	allow if input.context.approval.verified

	ctx := {"approval": input.context.approval} if {
		allow
		input.context.approval
	}

	ctx := {"reason": "approval_required", "access_request": {"template": "manager_approval"}} if {
		not allow
		not input.context.approval
	}

	# A re-evaluation whose approval no longer counts: say why, and ask
	# for a new request.
	ctx := {
		"reason": input.context.approval.reason,
		"next_action": "request",
		"access_request": {"template": "manager_approval"},
	} if {
		not allow
		input.context.approval
	}

	ars_caller := true

	ars_workflow := {"steps": [{"name": "manager_approval", "approvers": [{"type": "user", "id": "manager"}]}]}

	ars_approver := true
`

type serviceFixture struct {
	p      *AuthZenPlugin
	mux    *http.ServeMux
	idpKey jwk.Key
	store  store.Store
}

func newServiceFixture(t *testing.T, st store.Store, edits ...func(c map[string]any, idpJWKS string)) *serviceFixture {
	t.Helper()
	f := &serviceFixture{store: st}
	_, _, f.idpKey = testKey(t, t.TempDir(), "idp-1")
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pub, _ := f.idpKey.PublicKey()
		set := jwk.NewSet()
		_ = set.AddKey(pub)
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(idp.Close)
	t.Setenv(defaultDSNEnv, "postgres://unused")
	conf := serviceConf(t, func(c map[string]any) {
		c["decision_context"] = "ctx"
		s := service(c)
		s["caller_auth"] = map[string]any{"issuers": []any{map[string]any{"issuer": "https://idp.example.com", "audience": pdpID, "jwks_uri": idp.URL}}}
		s["approver_auth"] = map[string]any{"issuers": []any{map[string]any{"issuer": "https://idp.example.com", "audience": "approver-api", "jwks_uri": idp.URL}}}
		for _, edit := range edits {
			edit(c, idp.URL)
		}
	})
	cfg, err := Validate(nil, conf)
	if err != nil {
		t.Fatal(err)
	}
	p := testPlugin(t, serviceModule)
	p.cfg = *cfg
	p.openStore = func(context.Context, *ServiceConfig) (store.Store, error) { return st, nil }
	if err := p.startService(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.stopService)
	f.p = p
	f.mux = http.NewServeMux()
	for _, pattern := range ars.RoutePatterns() {
		f.mux.HandleFunc(pattern, p.serveARS(pattern))
	}
	return f
}

// signWith signs payload with an ES256 test key, naming its kid.
func signWith(t *testing.T, key jwk.Key, payload []byte) string {
	t.Helper()
	hdr := jws.NewHeaders()
	kid, _ := key.KeyID()
	_ = hdr.Set(jws.KeyIDKey, kid)
	out, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func (f *serviceFixture) token(t *testing.T, aud, sub string) string {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"iss": "https://idp.example.com", "aud": aud, "sub": sub, "exp": time.Now().Add(time.Hour).Unix()})
	return signWith(t, f.idpKey, payload)
}

func (f *serviceFixture) call(t *testing.T, method, path, token string, body any) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, req)
	if w.Code >= 300 {
		t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func bobEvaluation(approval string) string {
	ctx := `{"project": "renewal"}`
	if approval != "" {
		ctx = fmt.Sprintf(`{"project": "renewal", "approval": %s}`, approval)
	}
	return fmt.Sprintf(`{
		"subject": {"type": "user", "id": "bob"},
		"resource": {"type": "document", "id": "q4-plan"},
		"action": {"name": "can_read"},
		"context": %s
	}`, ctx)
}

func TestServiceEndToEnd(t *testing.T) {
	runEndToEnd(t, store.NewMemory())
}

// TestServiceEndToEndPostgres runs the same flow against Postgres, in a
// schema of its own. It needs AUTHZEN_ARS_TEST_DSN, such as a throwaway
// local container.
func TestServiceEndToEndPostgres(t *testing.T) {
	dsn := os.Getenv("AUTHZEN_ARS_TEST_DSN")
	if dsn == "" {
		t.Skip("AUTHZEN_ARS_TEST_DSN not set")
	}
	schema := fmt.Sprintf("ars_e2e_%d", os.Getpid())
	st, err := store.OpenPostgres(context.Background(), dsn, schema, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, err := store.OpenPostgres(context.Background(), dsn, schema, 1)
		if err == nil {
			cleanup.DropSchemaForTest(context.Background(), schema)
			cleanup.Close()
		}
	})
	runEndToEnd(t, st)
}

func runEndToEnd(t *testing.T, st store.Store) {
	f := newServiceFixture(t, st)

	// 1. Bob is denied, requestably, with a signed binding_token.
	decision, denialCtx := decisionContextOf(t, postEvaluation(f.p, bobEvaluation("")))
	if decision {
		t.Fatal("expected a denial")
	}
	ar := denialCtx["access_request"].(map[string]any)
	if ar["binding_token"] == nil {
		t.Fatalf("no binding_token: %v", denialCtx)
	}

	// 2. His agent submits the access request.
	submitted := f.call(t, http.MethodPost, ars.RequestsPath, f.token(t, pdpID, "agent-7"), map[string]any{
		"subject":  map[string]any{"type": "user", "id": "bob"},
		"resource": map[string]any{"type": "document", "id": "q4-plan"},
		"action":   map[string]any{"name": "can_read"},
		"context":  map[string]any{"project": "renewal"},
		"denial": map[string]any{
			"expires_at":    ar["expires_at"],
			"evaluation_id": denialCtx["evaluation_id"],
			"binding_token": ar["binding_token"],
			"template":      ar["template"],
		},
	})
	taskID := submitted["task"].(map[string]any)["id"].(string)

	// 3. The manager approves in the UI.
	f.call(t, http.MethodPost, ars.AdminPath+"/tasks/"+taskID+"/decisions", f.token(t, "approver-api", "manager"), map[string]any{"decision": "approve"})
	status := f.call(t, http.MethodGet, ars.RequestsPath+"/"+taskID, f.token(t, pdpID, "agent-7"), nil)
	approval := status["result"].(map[string]any)["approval"].(map[string]any)
	approvalJSON, _ := json.Marshal(approval)

	// 4. Re-evaluation with the approval permits, and the policy saw it
	// verified from the store, not from what the PEP sent.
	decision, permitCtx := decisionContextOf(t, postEvaluation(f.p, bobEvaluation(string(approvalJSON))))
	if !decision {
		t.Fatalf("expected the approved re-evaluation to permit: %v", permitCtx)
	}
	seen := permitCtx["approval"].(map[string]any)
	if seen["verified"] != true || seen["task_id"] != taskID || seen["issuer"] != pdpID {
		t.Fatalf("policy saw %v", seen)
	}

	// The approval is bound to this request: another resource is out of scope.
	other := `{"subject": {"type": "user", "id": "bob"}, "resource": {"type": "document", "id": "q3-plan"},
		"action": {"name": "can_read"}, "context": {"project": "renewal", "approval": ` + string(approvalJSON) + `}}`
	if decision, ctx := decisionContextOf(t, postEvaluation(f.p, other)); decision || ctx["reason"] != "out_of_scope" {
		t.Fatalf("expected out_of_scope, got %v %v", decision, ctx)
	}

	// 5. The approval is revoked; the next re-evaluation is denied and asks
	// for a new request.
	f.call(t, http.MethodPost, ars.AdminPath+"/approvals/"+approval["id"].(string)+"/revoke", f.token(t, "approver-api", "manager"), map[string]any{"reason": "no longer needed"})
	decision, revokedCtx := decisionContextOf(t, postEvaluation(f.p, bobEvaluation(string(approvalJSON))))
	if decision || revokedCtx["reason"] != "approval_expired" || revokedCtx["next_action"] != "request" || revokedCtx["access_request"] == nil {
		t.Fatalf("expected a revoked approval to be denied with next_action request: %v %v", decision, revokedCtx)
	}
}

func TestServiceForgedApprovalNotVerified(t *testing.T) {
	f := newServiceFixture(t, store.NewMemory())
	// An approval the store does not hold, with a PEP-asserted verified flag.
	decision, ctx := decisionContextOf(t, postEvaluation(f.p, bobEvaluation(`{"id": "apr_forged", "verified": true}`)))
	if decision || ctx["reason"] != "approval_unverifiable" {
		t.Fatalf("expected approval_unverifiable, got %v %v", decision, ctx)
	}
}

// failingStore is a store whose approval lookups fail.
type failingStore struct{ *store.Memory }

func (failingStore) GetApproval(context.Context, string) (*store.Approval, error) {
	return nil, errors.New("connection refused")
}

func TestServiceStoreFailureFailsEvaluation(t *testing.T) {
	f := newServiceFixture(t, failingStore{store.NewMemory()})
	w := postEvaluation(f.p, bobEvaluation(`{"id": "apr_1"}`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("a store outage must fail the evaluation, got %d: %s", w.Code, w.Body.String())
	}
	// Without an approval the store is not consulted.
	if w := postEvaluation(f.p, bobEvaluation("")); w.Code != http.StatusOK {
		t.Fatalf("an evaluation without an approval: %d", w.Code)
	}
	batch := `{"action": {"name": "can_read"}, "resource": {"type": "document", "id": "q4-plan"},
		"evaluations": [{"subject": {"type": "user", "id": "alice"}},
		                {"subject": {"type": "user", "id": "bob"}, "context": {"approval": {"id": "apr_1"}}}]}`
	resp := decodeBatchResp(t, postEvaluations(f.p, batch))
	if !resp.Evaluations[0].Decision || resp.Evaluations[1].Decision || !bytes.Contains(resp.Evaluations[1].Context, []byte(`"status":500`)) {
		t.Fatalf("batch: %+v", resp.Evaluations)
	}
}

func TestServiceStartFailsWhenStoreUnavailable(t *testing.T) {
	t.Setenv(defaultDSNEnv, "postgres://unused")
	cfg, err := Validate(nil, serviceConf(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	p := testPlugin(t, serviceModule)
	p.cfg = *cfg
	p.openStore = func(context.Context, *ServiceConfig) (store.Store, error) {
		return nil, errors.New("connection refused")
	}
	if err := p.Start(context.Background()); err == nil {
		t.Fatal("Start must fail when the store cannot be opened")
	}
}

func TestServiceRoutesUnavailableAfterStop(t *testing.T) {
	f := newServiceFixture(t, store.NewMemory())
	f.p.Stop(context.Background())
	req := httptest.NewRequest(http.MethodGet, ars.RequestsPath+"/arq_1", nil)
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 after Stop, got %d", w.Code)
	}
}

func TestServiceMetadataAdvertisesHostedEndpoint(t *testing.T) {
	f := newServiceFixture(t, store.NewMemory())
	md := wellKnownPDP(t, f.p, "pdp.example.com", nil)
	if md.AccessRequestEndpoint != pdpID+ars.RequestsPath {
		t.Fatalf("access_request_endpoint: %q", md.AccessRequestEndpoint)
	}
}
