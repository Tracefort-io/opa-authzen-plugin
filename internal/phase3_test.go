package internal

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars"
	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

const peerID = "https://peer-pdp.example.com"

// approveBob runs a requestable denial, submission and manager approval
// through the fixture and returns the task's result approval, as JSON and
// decoded.
func approveBob(t *testing.T, f *serviceFixture) (string, map[string]any) {
	t.Helper()
	_, denialCtx := decisionContextOf(t, postEvaluation(f.p, bobEvaluation("")))
	ar := denialCtx["access_request"].(map[string]any)
	submitted := f.call(t, http.MethodPost, ars.RequestsPath, f.token(t, pdpID, "agent-7"), map[string]any{
		"subject":  map[string]any{"type": "user", "id": "bob"},
		"resource": map[string]any{"type": "document", "id": "q4-plan"},
		"action":   map[string]any{"name": "can_read"},
		"context":  map[string]any{"project": "renewal"},
		"denial": map[string]any{
			"expires_at": ar["expires_at"], "evaluation_id": denialCtx["evaluation_id"],
			"binding_token": ar["binding_token"], "template": ar["template"],
		},
	})
	taskID := submitted["task"].(map[string]any)["id"].(string)
	f.call(t, http.MethodPost, ars.AdminPath+"/tasks/"+taskID+"/decisions", f.token(t, "approver-api", "manager"), map[string]any{"decision": "approve"})
	status := f.call(t, http.MethodGet, ars.RequestsPath+"/"+taskID, f.token(t, pdpID, "agent-7"), nil)
	approval := status["result"].(map[string]any)["approval"].(map[string]any)
	b, _ := json.Marshal(approval)
	return string(b), approval
}

// countingStore counts approval lookups.
type countingStore struct {
	store.Store
	gets atomic.Int32
}

func (c *countingStore) GetApproval(ctx context.Context, id string) (*store.Approval, error) {
	c.gets.Add(1)
	return c.Store.GetApproval(ctx, id)
}

func TestApprovalCache(t *testing.T) {
	st := &countingStore{Store: store.NewMemory()}
	f := newServiceFixture(t, st, func(c map[string]any, _ string) { service(c)["approval_cache_ttl"] = "5m" })
	approvalJSON, approval := approveBob(t, f)
	before := st.gets.Load()

	for i := range 3 {
		if decision, ctx := decisionContextOf(t, postEvaluation(f.p, bobEvaluation(approvalJSON))); !decision {
			t.Fatalf("re-evaluation %d: %v", i, ctx)
		}
	}
	if got := st.gets.Load() - before; got != 1 {
		t.Fatalf("three re-evaluations made %d store lookups, want 1", got)
	}
	// Scope is still checked on a cached approval.
	other := strings.Replace(bobEvaluation(approvalJSON), "q4-plan", "q3-plan", 1)
	if decision, ctx := decisionContextOf(t, postEvaluation(f.p, other)); decision || ctx["reason"] != "out_of_scope" {
		t.Fatalf("cached approval out of scope: %v %v", decision, ctx)
	}

	// A revocation on another replica (straight in the store) is not seen
	// until the entry lapses: the trade-off approval_cache_ttl makes.
	id := approval["id"].(string)
	if _, err := st.RevokeApproval(context.Background(), id, "elsewhere", "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	if decision, _ := decisionContextOf(t, postEvaluation(f.p, bobEvaluation(approvalJSON))); !decision {
		t.Fatal("the cache should still hold the approval within its TTL")
	}
	f.p.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
	if decision, ctx := decisionContextOf(t, postEvaluation(f.p, bobEvaluation(approvalJSON))); decision || ctx["reason"] != "approval_expired" {
		t.Fatalf("after the TTL the revocation counts: %v %v", decision, ctx)
	}
}

func TestApprovalCacheDroppedOnLocalRevoke(t *testing.T) {
	f := newServiceFixture(t, store.NewMemory(), func(c map[string]any, _ string) { service(c)["approval_cache_ttl"] = "1h" })
	approvalJSON, approval := approveBob(t, f)
	if decision, _ := decisionContextOf(t, postEvaluation(f.p, bobEvaluation(approvalJSON))); !decision {
		t.Fatal("not permitted before revocation")
	}
	f.call(t, http.MethodPost, ars.AdminPath+"/approvals/"+approval["id"].(string)+"/revoke", f.token(t, "approver-api", "manager"), nil)
	if decision, ctx := decisionContextOf(t, postEvaluation(f.p, bobEvaluation(approvalJSON))); decision || ctx["reason"] != "approval_expired" {
		t.Fatalf("a revocation through this replica takes effect at once: %v %v", decision, ctx)
	}
}

func stateClaims(t *testing.T, state string) map[string]any {
	t.Helper()
	parts := strings.Split(state, ".")
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	_ = json.Unmarshal(b, &claims)
	return claims
}

// TestPeerPDP runs a second plugin that holds no store and trusts the
// first only through approval_issuers with jwks_uri (design §19.4).
func TestPeerPDP(t *testing.T) {
	a := newServiceFixture(t, store.NewMemory(), func(c map[string]any, _ string) {
		service(c)["approval_state_ttl"] = "10m"
		service(c)["approval_state_audiences"] = []any{peerID}
	})
	jwks := httptest.NewServer(http.HandlerFunc(a.p.handleJWKS))
	t.Cleanup(jwks.Close)
	approvalJSON, approval := approveBob(t, a)

	claims := stateClaims(t, approval["state"].(string))
	aud, _ := claims["aud"].([]any)
	if len(aud) != 2 || aud[0] != pdpID || aud[1] != peerID {
		t.Fatalf("aud %v", claims["aud"])
	}
	until, _ := time.Parse(time.RFC3339, approval["approved_until"].(string))
	exp := time.Unix(int64(claims["exp"].(float64)), 0)
	if exp.After(time.Now().Add(10*time.Minute+time.Second)) || !exp.Before(until) {
		t.Fatalf("exp %v not capped by approval_state_ttl (approved_until %v)", exp, until)
	}

	b := testPlugin(t, serviceModule)
	cfg, err := Validate(nil, []byte(`{"base_url": "`+peerID+`", "decision_context": "ctx",
		"access_request_endpoint": "https://pdp.example.com/access/v1/requests",
		"access_request": {"approval_issuers": [{"issuer": "`+pdpID+`", "jwks_uri": "`+jwks.URL+`"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	b.cfg = *cfg

	decision, ctx := decisionContextOf(t, postEvaluation(b, bobEvaluation(approvalJSON)))
	if !decision || ctx["approval"].(map[string]any)["issuer"] != pdpID {
		t.Fatalf("the peer did not accept the signed approval: %v %v", decision, ctx)
	}
	// The peer republishes the trusted issuer's keys in its own JWK Set.
	w := httptest.NewRecorder()
	b.handleJWKS(w, httptest.NewRequest(http.MethodGet, jwksPath, nil))
	if set, err := jwk.Parse(w.Body.Bytes()); err != nil || set.Len() != 1 {
		t.Fatalf("peer JWK Set: %d %s", w.Code, w.Body.String())
	}

	// The peer cannot see a revocation; it honours the state until exp.
	a.call(t, http.MethodPost, ars.AdminPath+"/approvals/"+approval["id"].(string)+"/revoke", a.token(t, "approver-api", "manager"), nil)
	if decision, _ := decisionContextOf(t, postEvaluation(b, bobEvaluation(approvalJSON))); !decision {
		t.Fatal("expected the peer to still accept the state before its exp")
	}
	if decision, _ := decisionContextOf(t, postEvaluation(a.p, bobEvaluation(approvalJSON))); decision {
		t.Fatal("the issuing PDP must see the revocation")
	}
	b.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if decision, ctx := decisionContextOf(t, postEvaluation(b, bobEvaluation(approvalJSON))); decision || ctx["reason"] != "approval_expired" {
		t.Fatalf("past approval_state_ttl the peer must refuse: %v %v", decision, ctx)
	}
}

// pepModule permits only the procurement app's PEP.
const pepModule = `
	package authzen

	default allow := false

	allow if input.pep.client_id == "procurement-app"
`

func TestPEPAuth(t *testing.T) {
	_, _, idpKey := testKey(t, t.TempDir(), "idp-1")
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pub, _ := idpKey.PublicKey()
		set := jwk.NewSet()
		_ = set.AddKey(pub)
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(idp.Close)
	cfg, err := Validate(nil, []byte(`{"base_url": "`+pdpID+`",
		"pep_auth": {"issuers": [{"issuer": "https://idp.example.com", "audience": "`+pdpID+`", "jwks_uri": "`+idp.URL+`"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	p := testPlugin(t, pepModule)
	p.cfg = *cfg
	handler := p.withPEPAuth(p.handleEvaluation)
	token := func(aud, client string) string {
		payload, _ := json.Marshal(map[string]any{"iss": "https://idp.example.com", "aud": aud, "sub": "svc-1", "client_id": client, "exp": time.Now().Add(time.Hour).Unix()})
		return signWith(t, idpKey, payload)
	}
	call := func(auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(singleEvalBody))
		r.Header.Set("Content-Type", "application/json")
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		r.Header.Set("X-Request-ID", "req-1")
		w := httptest.NewRecorder()
		handler(w, r)
		return w
	}

	w := call("")
	if w.Code != http.StatusUnauthorized || !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Bearer ") || w.Header().Get("X-Request-ID") != "req-1" {
		t.Fatalf("no token: %d %v", w.Code, w.Header())
	}
	if w := call("Bearer " + token("https://other.example.com", "procurement-app")); w.Code != http.StatusUnauthorized ||
		!strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("wrong audience: %d %v", w.Code, w.Header())
	}
	// The policy sees the PEP: the procurement app is allowed, another
	// authenticated PEP is not.
	for client, want := range map[string]bool{"procurement-app": true, "other-app": false} {
		w := call("Bearer " + token(pdpID, client))
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != http.StatusOK || body["decision"] != want {
			t.Fatalf("%s: %d %s", client, w.Code, w.Body.String())
		}
	}

	// Without pep_auth nothing changes: no token needed, no input.pep.
	open := testPlugin(t, pepModule)
	w = httptest.NewRecorder()
	openReq := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", bytes.NewBufferString(singleEvalBody))
	openReq.Header.Set("Content-Type", "application/json")
	open.withPEPAuth(open.handleEvaluation)(w, openReq)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"decision":false`) {
		t.Fatalf("without pep_auth: %d %s", w.Code, w.Body.String())
	}
}

// dpopProof signs a DPoP proof for a request with key.
func dpopProof(t *testing.T, key jwk.Key, token, method, htu, jti string) string {
	t.Helper()
	hash := sha256.Sum256([]byte(token))
	payload, _ := json.Marshal(map[string]any{
		"jti": jti, "htm": method, "htu": htu, "iat": time.Now().Unix(),
		"ath": base64.RawURLEncoding.EncodeToString(hash[:]),
	})
	pub, _ := key.PublicKey()
	hdr := jws.NewHeaders()
	_ = hdr.Set(jws.TypeKey, "dpop+jwt")
	_ = hdr.Set(jws.JWKKey, pub)
	out, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// TestServiceDPoP requires DPoP-bound tokens on the caller API; proofs are
// remembered in the shared store, so a replay is refused.
func TestServiceDPoP(t *testing.T) {
	st := store.NewMemory()
	f := newServiceFixture(t, st, func(c map[string]any, idpJWKS string) {
		service(c)["caller_auth"] = map[string]any{
			"issuers":           []any{map[string]any{"issuer": "https://idp.example.com", "audience": pdpID, "jwks_uri": idpJWKS}},
			"sender_constraint": map[string]any{"require": true, "dpop": map[string]any{"enabled": true}},
		}
	})
	_, _, client := testKey(t, t.TempDir(), "agent-key")
	pub, _ := client.PublicKey()
	thumb, _ := pub.Thumbprint(crypto.SHA256)
	payload, _ := json.Marshal(map[string]any{
		"iss": "https://idp.example.com", "aud": pdpID, "sub": "agent-7", "exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]any{"jkt": base64.RawURLEncoding.EncodeToString(thumb)},
	})
	token := signWith(t, f.idpKey, payload)
	get := func(scheme, proof string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, ars.RequestsPath+"/arq_missing", nil)
		r.Header.Set("Authorization", scheme+" "+token)
		if proof != "" {
			r.Header.Set("DPoP", proof)
		}
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, r)
		return w
	}
	proof := dpopProof(t, client, token, http.MethodGet, pdpID+ars.RequestsPath+"/arq_missing", "p-1")
	// Authenticated: the task is simply unknown.
	if w := get("DPoP", proof); w.Code != http.StatusNotFound {
		t.Fatalf("valid DPoP: %d %s", w.Code, w.Body.String())
	}
	w := get("DPoP", proof)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), `DPoP realm=`) ||
		!strings.Contains(w.Header().Get("WWW-Authenticate"), "invalid_dpop_proof") {
		t.Fatalf("replayed proof: %d %v", w.Code, w.Header())
	}
	// The replay record is in the shared store, where every replica sees it.
	jkt := base64.RawURLEncoding.EncodeToString(thumb)
	if fresh, _ := st.RememberJTI(context.Background(), "dpop:"+jkt+":p-1", time.Now().Add(time.Minute)); fresh {
		t.Fatal("the proof was not recorded in the store")
	}
	// A bound token sent as a bearer token is refused.
	if w := get("Bearer", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("bound token as bearer: %d", w.Code)
	}
}

// metricSum is a counter's total over the data points carrying attrs.
func metricSum(rm *metricdata.ResourceMetrics, name string, attrs map[string]string) (int64, bool) {
	var total int64
	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			switch d := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, dp := range d.DataPoints {
					if matches(dp.Attributes.ToSlice(), attrs) {
						total += dp.Value
						found = true
					}
				}
			case metricdata.Gauge[int64]:
				for _, dp := range d.DataPoints {
					total, found = dp.Value, true
				}
			}
		}
	}
	return total, found
}

func matches(kvs []attribute.KeyValue, want map[string]string) bool {
	for k, v := range want {
		ok := false
		for _, kv := range kvs {
			if string(kv.Key) == k && kv.Value.AsString() == v {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func TestMetrics(t *testing.T) {
	f := newServiceFixture(t, store.NewMemory())
	reader := sdkmetric.NewManualReader()
	m, err := newMetricsWithReader(context.Background(), reader, func() store.Store { return f.store })
	if err != nil {
		t.Fatal(err)
	}
	f.p.metrics.set(m)
	approvalJSON, _ := approveBob(t, f)
	postEvaluation(f.p, bobEvaluation(approvalJSON))
	// One rejected submission: no token.
	r := httptest.NewRequest(http.MethodPost, ars.RequestsPath, bytes.NewBufferString(`{}`))
	f.mux.ServeHTTP(httptest.NewRecorder(), r)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		attrs map[string]string
		want  int64
	}{
		{ars.MetricSubmissions, map[string]string{"outcome": "pending"}, 1},
		{ars.MetricDecisions, map[string]string{"decision": "approve"}, 1},
		{ars.MetricTransitions, map[string]string{"status": "approved"}, 1},
		{ars.MetricApprovalLookups, map[string]string{"result": "verified", "cached": "false"}, 1},
		{ars.MetricAuthFailures, map[string]string{"api": "caller", "reason": "missing_credentials"}, 1},
		{ars.MetricPendingTasks, nil, 0},
	} {
		got, found := metricSum(&rm, c.name, c.attrs)
		if !found || got != c.want {
			t.Errorf("%s %v = %d (found %v), want %d", c.name, c.attrs, got, found, c.want)
		}
	}
}
