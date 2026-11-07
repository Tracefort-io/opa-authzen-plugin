package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

const apiBase = "https://pdp.example.com"

func constrained(t *testing.T, ti *testIssuer, sc *SenderConstraint) *Verifier {
	t.Helper()
	v := verifier(t, ti)
	replay := NewMemoryReplay()
	replay.now = func() time.Time { return now }
	if err := v.WithSenderConstraint(sc, apiBase, replay); err != nil {
		t.Fatal(err)
	}
	return v
}

func thumbprint(t *testing.T, key jwk.Key) string {
	t.Helper()
	pub, _ := key.PublicKey()
	b, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// dpopProof signs a DPoP proof with key, after edit changes its claims or
// header.
func dpopProof(t *testing.T, key jwk.Key, token, method, htu string, edit func(claims map[string]any, hdr jws.Headers)) string {
	t.Helper()
	hash := sha256.Sum256([]byte(token))
	claims := map[string]any{
		"jti": "proof-" + method + htu, "htm": method, "htu": htu,
		"iat": float64(now.Unix()), "ath": base64.RawURLEncoding.EncodeToString(hash[:]),
	}
	pub, _ := key.PublicKey()
	hdr := jws.NewHeaders()
	_ = hdr.Set(jws.TypeKey, "dpop+jwt")
	_ = hdr.Set(jws.JWKKey, pub)
	if edit != nil {
		edit(claims, hdr)
	}
	payload, _ := json.Marshal(claims)
	out, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func boundClaims(cnf map[string]any) map[string]any {
	c := validClaims()
	c["cnf"] = cnf
	return c
}

func TestDPoP(t *testing.T) {
	ti := newTestIssuer(t, "k1")
	client := newKey(t, "client")
	other := newKey(t, "other")
	token := sign(t, ti.priv, boundClaims(map[string]any{"jkt": thumbprint(t, client)}))
	path := "/access/v1/requests"

	request := func(scheme, tok, proof string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, path+"?x=1", nil)
		r.Header.Set("Authorization", scheme+" "+tok)
		if proof != "" {
			r.Header.Set("DPoP", proof)
		}
		return r
	}
	good := func(edit func(map[string]any, jws.Headers)) string {
		return dpopProof(t, client, token, http.MethodPost, apiBase+path, edit)
	}

	v := constrained(t, ti, &SenderConstraint{DPoP: &DPoPConfig{Enabled: true}})
	if _, err := v.Authenticate(request("DPoP", token, good(nil))); err != nil {
		t.Fatalf("valid proof: %v", err)
	}
	// Default port and host case do not matter; the query is ignored.
	v = constrained(t, ti, &SenderConstraint{DPoP: &DPoPConfig{Enabled: true}})
	if _, err := v.Authenticate(request("DPoP", token, dpopProof(t, client, token, http.MethodPost, "https://PDP.example.com:443"+path, nil))); err != nil {
		t.Fatalf("normalized htu: %v", err)
	}

	cases := map[string]*http.Request{
		"bound token as bearer": request("Bearer", token, good(nil)),
		"no proof":              request("DPoP", token, ""),
		"other key": request("DPoP", token, dpopProof(t, other, token, http.MethodPost, apiBase+path, func(c map[string]any, _ jws.Headers) {
			c["jti"] = "other"
		})),
		"wrong method": request("DPoP", token, dpopProof(t, client, token, http.MethodGet, apiBase+path, nil)),
		"wrong url":    request("DPoP", token, dpopProof(t, client, token, http.MethodPost, apiBase+"/access/v1/admin/tasks", nil)),
		"wrong typ":    request("DPoP", token, good(func(_ map[string]any, h jws.Headers) { _ = h.Set(jws.TypeKey, "JWT") })),
		"other token":  request("DPoP", token, good(func(c map[string]any, _ jws.Headers) { c["ath"] = "x" })),
		"too old":      request("DPoP", token, good(func(c map[string]any, _ jws.Headers) { c["iat"] = float64(now.Add(-5 * time.Minute).Unix()) })),
		"from future":  request("DPoP", token, good(func(c map[string]any, _ jws.Headers) { c["iat"] = float64(now.Add(5 * time.Minute).Unix()) })),
		"no jti":       request("DPoP", token, good(func(c map[string]any, _ jws.Headers) { delete(c, "jti") })),
		"private jwk":  request("DPoP", token, good(func(_ map[string]any, h jws.Headers) { _ = h.Set(jws.JWKKey, client) })),
		"two proofs": func() *http.Request {
			r := request("DPoP", token, good(nil))
			r.Header.Add("DPoP", good(nil))
			return r
		}(),
		"unbound w/DPoP": request("DPoP", sign(t, ti.priv, validClaims()), good(nil)),
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			v := constrained(t, ti, &SenderConstraint{DPoP: &DPoPConfig{Enabled: true}})
			_, err := v.Authenticate(r)
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("expected rejection, got %v", err)
			}
			t.Log(err)
		})
	}

	// A proof is accepted once.
	v = constrained(t, ti, &SenderConstraint{DPoP: &DPoPConfig{Enabled: true}})
	proof := good(nil)
	if _, err := v.Authenticate(request("DPoP", token, proof)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Authenticate(request("DPoP", token, proof)); Reason(err) != "invalid_dpop_proof" {
		t.Fatalf("replayed proof: %v", err)
	}

	// Without DPoP enabled, the scheme and bound tokens are refused.
	plain := verifier(t, ti)
	if _, err := plain.Authenticate(request("DPoP", token, good(nil))); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("DPoP without the option: %v", err)
	}
}

func TestDPoPChallenge(t *testing.T) {
	ti := newTestIssuer(t, "k1")
	v := constrained(t, ti, &SenderConstraint{Require: true, DPoP: &DPoPConfig{Enabled: true}})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+sign(t, ti.priv, validClaims()))
	_, err := v.Authenticate(r)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unbound token with require: %v", err)
	}
	got := v.Challenges("pdp", err)
	if len(got) != 1 || !strings.HasPrefix(got[0], "DPoP ") || !strings.Contains(got[0], `error="invalid_token"`) || !strings.Contains(got[0], "algs=") {
		t.Fatalf("challenges: %v", got)
	}
}

func newCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pep"}, NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func TestMTLSBound(t *testing.T) {
	ti := newTestIssuer(t, "k1")
	cert, stranger := newCert(t), newCert(t)
	sum := sha256.Sum256(cert.Raw)
	token := sign(t, ti.priv, boundClaims(map[string]any{"x5t#S256": base64.RawURLEncoding.EncodeToString(sum[:])}))
	escapedPEM := url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
	strangerSum := sha256.Sum256(stranger.Raw)

	request := func(edit func(*http.Request)) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		edit(r)
		return r
	}
	viaTLS := &SenderConstraint{MTLS: &MTLSConfig{Enabled: true, Source: MTLSSourceTLS}}
	xfcc := &SenderConstraint{MTLS: &MTLSConfig{Enabled: true, Source: MTLSSourceHeader, Header: "X-Forwarded-Client-Cert", Format: FormatEnvoyXFCC}}
	pemHeader := &SenderConstraint{MTLS: &MTLSConfig{Enabled: true, Source: MTLSSourceHeader, Header: "Ssl-Client-Cert", Format: FormatPEM}}

	cases := map[string]struct {
		sc *SenderConstraint
		r  *http.Request
		ok bool
	}{
		"tls cert": {viaTLS, request(func(r *http.Request) { r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}} }), true},
		"tls other cert": {viaTLS, request(func(r *http.Request) {
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{stranger}}
		}), false},
		"tls none": {viaTLS, request(func(*http.Request) {}), false},
		"xfcc hash": {xfcc, request(func(r *http.Request) {
			r.Header.Set("X-Forwarded-Client-Cert", `By=spiffe://pdp;Hash=`+hex.EncodeToString(sum[:])+`;Subject="CN=pep,O=a;b"`)
		}), true},
		"xfcc last element counts": {xfcc, request(func(r *http.Request) {
			r.Header.Set("X-Forwarded-Client-Cert", "Hash="+hex.EncodeToString(sum[:])+",Hash="+hex.EncodeToString(strangerSum[:]))
		}), false},
		"xfcc cert only": {xfcc, request(func(r *http.Request) { r.Header.Set("X-Forwarded-Client-Cert", `Cert="`+escapedPEM+`"`) }), true},
		"xfcc absent":    {xfcc, request(func(*http.Request) {}), false},
		"pem header":     {pemHeader, request(func(r *http.Request) { r.Header.Set("Ssl-Client-Cert", escapedPEM) }), true},
		"not enabled":    {nil, request(func(r *http.Request) { r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}} }), false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			v := verifier(t, ti)
			if c.sc != nil {
				v = constrained(t, ti, c.sc)
			}
			_, err := v.Authenticate(c.r)
			if (err == nil) != c.ok {
				t.Fatalf("ok=%v, err=%v", c.ok, err)
			}
		})
	}
}

func TestSenderConstraintValidate(t *testing.T) {
	for name, sc := range map[string]*SenderConstraint{
		"require without mechanism": {Require: true},
		"bad max age":               {DPoP: &DPoPConfig{Enabled: true, MaxAge: "soon"}},
		"bad source":                {MTLS: &MTLSConfig{Enabled: true, Source: "magic"}},
		"header without name":       {MTLS: &MTLSConfig{Enabled: true, Source: MTLSSourceHeader, Format: FormatPEM}},
		"header without format":     {MTLS: &MTLSConfig{Enabled: true, Source: MTLSSourceHeader, Header: "X"}},
	} {
		if err := sc.Validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// Unbound bearer tokens still pass with an optional constraint.
	ti := newTestIssuer(t, "k1")
	v := constrained(t, ti, &SenderConstraint{DPoP: &DPoPConfig{Enabled: true}})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+sign(t, ti.priv, validClaims()))
	if _, err := v.Authenticate(r); err != nil {
		t.Fatalf("bearer token with optional DPoP: %v", err)
	}
}
