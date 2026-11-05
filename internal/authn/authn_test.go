package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

type testIssuer struct {
	priv    jwk.Key
	server  *httptest.Server
	fetches atomic.Int32
}

func newTestIssuer(t *testing.T, kid string) *testIssuer {
	t.Helper()
	ti := &testIssuer{}
	ti.priv = newKey(t, kid)
	ti.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ti.fetches.Add(1)
		pub, _ := ti.priv.PublicKey()
		set := jwk.NewSet()
		_ = set.AddKey(pub)
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(ti.server.Close)
	return ti
}

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

func sign(t *testing.T, key jwk.Key, claims map[string]any) string {
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

var now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func validClaims() map[string]any {
	return map[string]any{
		"iss":       "https://idp.example.com",
		"aud":       []any{"https://pdp.example.com", "other"},
		"sub":       "agent-7",
		"client_id": "renewal-assistant",
		"exp":       float64(now.Add(time.Hour).Unix()),
		"act":       map[string]any{"sub": "runtime-1"},
	}
}

func verifier(t *testing.T, ti *testIssuer) *Verifier {
	t.Helper()
	v, err := NewVerifier([]Issuer{{Issuer: "https://idp.example.com", Audience: "https://pdp.example.com", JWKSURI: ti.server.URL}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return now }
	return v
}

func TestVerifyAcceptsValidToken(t *testing.T) {
	ti := newTestIssuer(t, "k1")
	v := verifier(t, ti)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+sign(t, ti.priv, validClaims()))
	id, err := v.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if id.Iss != "https://idp.example.com" || id.Sub != "agent-7" || id.ClientID != "renewal-assistant" || id.Act["sub"] != "runtime-1" {
		t.Fatalf("identity: %+v", id)
	}
	if id.Key() != "https://idp.example.com|agent-7" {
		t.Fatalf("key: %s", id.Key())
	}
}

func TestVerifyRejects(t *testing.T) {
	ti := newTestIssuer(t, "k1")
	stranger := newKey(t, "k1")
	mutate := func(fn func(map[string]any)) map[string]any {
		c := validClaims()
		fn(c)
		return c
	}
	cases := map[string]string{
		"wrong signer":      sign(t, stranger, validClaims()),
		"untrusted issuer":  sign(t, ti.priv, mutate(func(c map[string]any) { c["iss"] = "https://evil.example" })),
		"wrong audience":    sign(t, ti.priv, mutate(func(c map[string]any) { c["aud"] = "someone-else" })),
		"expired":           sign(t, ti.priv, mutate(func(c map[string]any) { c["exp"] = float64(now.Add(-time.Hour).Unix()) })),
		"no exp":            sign(t, ti.priv, mutate(func(c map[string]any) { delete(c, "exp") })),
		"not yet valid":     sign(t, ti.priv, mutate(func(c map[string]any) { c["nbf"] = float64(now.Add(time.Hour).Unix()) })),
		"no sub":            sign(t, ti.priv, mutate(func(c map[string]any) { delete(c, "sub") })),
		"sender-constraint": sign(t, ti.priv, mutate(func(c map[string]any) { c["cnf"] = map[string]any{"jkt": "x"} })),
		"not a JWS":         "abc",
	}
	v := verifier(t, ti)
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), token); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("expected ErrUnauthenticated, got %v", err)
			}
		})
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := v.Authenticate(req); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("missing header: %v", err)
	}
}

func TestVerifyToleratesClockSkew(t *testing.T) {
	ti := newTestIssuer(t, "k1")
	v := verifier(t, ti)
	c := validClaims()
	c["exp"] = float64(now.Add(-10 * time.Second).Unix())
	if _, err := v.Verify(context.Background(), sign(t, ti.priv, c)); err != nil {
		t.Fatalf("a token 10s past exp is within the skew: %v", err)
	}
}

func TestJWKSCachedAndRefreshedOnRotation(t *testing.T) {
	ti := newTestIssuer(t, "k1")
	v := verifier(t, ti)
	for range 3 {
		if _, err := v.Verify(context.Background(), sign(t, ti.priv, validClaims())); err != nil {
			t.Fatal(err)
		}
	}
	if ti.fetches.Load() != 1 {
		t.Fatalf("expected one fetch for a cached set, got %d", ti.fetches.Load())
	}
	// Key rotation: an unknown kid refetches once the minimum interval has
	// passed.
	ti.priv = newKey(t, "k2")
	v.now = func() time.Time { return now.Add(time.Minute) }
	if _, err := v.Verify(context.Background(), sign(t, ti.priv, validClaims())); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
	if ti.fetches.Load() != 2 {
		t.Fatalf("expected a refetch on an unknown kid, got %d fetches", ti.fetches.Load())
	}
}

func TestNewVerifierValidates(t *testing.T) {
	for name, iss := range map[string][]Issuer{
		"none":         nil,
		"empty issuer": {{Audience: "a", JWKSURI: "https://x"}},
		"no audience":  {{Issuer: "i", JWKSURI: "https://x"}},
		"bad jwks":     {{Issuer: "i", Audience: "a", JWKSURI: "file:///x"}},
		"duplicate":    {{Issuer: "i", Audience: "a", JWKSURI: "https://x"}, {Issuer: "i", Audience: "b", JWKSURI: "https://y"}},
	} {
		if _, err := NewVerifier(iss, nil); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
