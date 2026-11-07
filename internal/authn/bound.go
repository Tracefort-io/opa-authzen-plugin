package authn

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// Sender-constrained tokens: DPoP (RFC 9449) and mTLS certificate-bound
// tokens (RFC 8705). A token naming a key in `cnf` is accepted only with
// proof that the caller holds that key.

// SenderConstraint configures proof of possession for one API.
type SenderConstraint struct {
	// Require refuses tokens that are not sender-constrained.
	Require bool        `json:"require,omitempty"`
	DPoP    *DPoPConfig `json:"dpop,omitempty"`
	MTLS    *MTLSConfig `json:"mtls,omitempty"`
}

// DPoPConfig enables DPoP-bound tokens.
type DPoPConfig struct {
	Enabled bool `json:"enabled"`
	// MaxAge bounds how old a proof's iat may be, as a Go duration.
	MaxAge string `json:"max_age,omitempty"`

	maxAge time.Duration
}

// MTLSConfig enables certificate-bound tokens.
type MTLSConfig struct {
	Enabled bool `json:"enabled"`
	// Source is "tls" (OPA terminates TLS) or "header" (a proxy forwards
	// the certificate in Header, in Format).
	Source string `json:"source"`
	Header string `json:"header,omitempty"`
	// Format is "envoy_xfcc" (Envoy's X-Forwarded-Client-Cert) or "pem"
	// (a URL-encoded PEM certificate).
	Format string `json:"format,omitempty"`
}

// Sources and formats of a client certificate.
const (
	MTLSSourceTLS    = "tls"
	MTLSSourceHeader = "header"
	FormatEnvoyXFCC  = "envoy_xfcc"
	FormatPEM        = "pem"
)

const (
	defaultDPoPMaxAge = 60 * time.Second
	// dpopAlgs are the asymmetric algorithms accepted for proofs.
	dpopAlgs = "ES256 ES384 RS256 PS256 EdDSA"
)

// Replay remembers proof identifiers: Remember returns false for one seen
// before, until exp.
type Replay interface {
	Remember(ctx context.Context, id string, exp time.Time) (bool, error)
}

// Validate checks the configuration and fills defaults.
func (c *SenderConstraint) Validate() error {
	if c == nil {
		return nil
	}
	if c.DPoP != nil && c.DPoP.Enabled {
		c.DPoP.maxAge = defaultDPoPMaxAge
		if s := strings.TrimSpace(c.DPoP.MaxAge); s != "" {
			d, err := time.ParseDuration(s)
			if err != nil || d <= 0 {
				return fmt.Errorf("dpop.max_age %q must be a positive duration", c.DPoP.MaxAge)
			}
			c.DPoP.maxAge = d
		}
	}
	if m := c.MTLS; m != nil && m.Enabled {
		switch m.Source {
		case MTLSSourceTLS:
		case MTLSSourceHeader:
			if strings.TrimSpace(m.Header) == "" {
				return errors.New("mtls.header is required with source header")
			}
			if m.Format != FormatEnvoyXFCC && m.Format != FormatPEM {
				return fmt.Errorf("mtls.format must be %q or %q", FormatEnvoyXFCC, FormatPEM)
			}
		default:
			return fmt.Errorf("mtls.source must be %q or %q", MTLSSourceTLS, MTLSSourceHeader)
		}
	}
	if c.Require && !c.dpopEnabled() && !c.mtlsEnabled() {
		return errors.New("require needs dpop or mtls enabled")
	}
	return nil
}

func (c *SenderConstraint) required() bool    { return c != nil && c.Require }
func (c *SenderConstraint) dpopEnabled() bool { return c != nil && c.DPoP != nil && c.DPoP.Enabled }
func (c *SenderConstraint) mtlsEnabled() bool { return c != nil && c.MTLS != nil && c.MTLS.Enabled }

// Error is an authentication failure with what the challenge needs.
type Error struct {
	// Code is the RFC 6750 / RFC 9449 error code: invalid_request,
	// invalid_token or invalid_dpop_proof; empty when no credentials came.
	Code   string
	Reason string
}

func (e *Error) Error() string { return ErrUnauthenticated.Error() + ": " + e.Reason }
func (e *Error) Unwrap() error { return ErrUnauthenticated }

func failure(code, format string, args ...any) error {
	return &Error{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// Reason is a short label for the failure, for metrics.
func Reason(err error) string {
	var e *Error
	if errors.As(err, &e) && e.Code != "" {
		return e.Code
	}
	if errors.As(err, &e) {
		return "missing_credentials"
	}
	return "invalid_token"
}

// Challenges are the WWW-Authenticate values for a 401 (RFC 6750 §3,
// RFC 9449 §7.1): Bearer when unbound tokens are accepted, DPoP when DPoP
// is enabled.
func (v *Verifier) Challenges(realm string, err error) []string {
	code, desc := "", ""
	var e *Error
	if errors.As(err, &e) {
		code, desc = e.Code, e.Reason
	}
	param := func(extra string) string {
		s := `realm="` + realm + `"`
		if code != "" {
			s += `, error="` + code + `", error_description="` + strings.ReplaceAll(desc, `"`, "'") + `"`
		}
		return s + extra
	}
	var out []string
	if !v.sc.required() || v.sc.mtlsEnabled() {
		out = append(out, "Bearer "+param(""))
	}
	if v.sc.dpopEnabled() {
		out = append(out, "DPoP "+param(`, algs="`+dpopAlgs+`"`))
	}
	return out
}

// WithSenderConstraint enables proof of possession. baseURL is the
// public base of the APIs, from which a DPoP proof's htu is checked;
// replay remembers proof identifiers. It must be called before use.
func (v *Verifier) WithSenderConstraint(sc *SenderConstraint, baseURL string, replay Replay) error {
	if err := sc.Validate(); err != nil {
		return err
	}
	if sc.dpopEnabled() && replay == nil {
		return errors.New("dpop needs a replay store")
	}
	v.sc, v.baseURL, v.replay = sc, strings.TrimRight(baseURL, "/"), replay
	return nil
}

// bind checks that the request proves possession of the key the token is
// bound to, as the scheme it came with requires.
func (v *Verifier) bind(r *http.Request, scheme, token string, claims map[string]any) error {
	cnf, hasCnf := claims["cnf"].(map[string]any)
	if _, present := claims["cnf"]; present && !hasCnf {
		return failure("invalid_token", "cnf must be an object")
	}
	jkt, _ := cnf["jkt"].(string)
	x5t, _ := cnf["x5t#S256"].(string)
	switch {
	case jkt != "":
		if !v.sc.dpopEnabled() {
			return failure("invalid_token", "DPoP-bound tokens are not accepted")
		}
		if scheme != "dpop" {
			return failure("invalid_token", "a DPoP-bound token must be sent with the DPoP scheme")
		}
		return v.checkDPoP(r, token, jkt)
	case scheme == "dpop":
		return failure("invalid_token", "the DPoP scheme needs a DPoP-bound token")
	case x5t != "":
		if !v.sc.mtlsEnabled() {
			return failure("invalid_token", "certificate-bound tokens are not accepted")
		}
		return v.checkMTLS(r, x5t)
	case hasCnf:
		return failure("invalid_token", "unsupported cnf confirmation method")
	case v.sc.required():
		return failure("invalid_token", "a sender-constrained token is required")
	}
	return nil
}

// checkDPoP verifies the request's DPoP proof (RFC 9449 §4.3).
func (v *Verifier) checkDPoP(r *http.Request, token, jkt string) error {
	invalid := func(format string, args ...any) error { return failure("invalid_dpop_proof", format, args...) }
	proofs := r.Header.Values("DPoP")
	if len(proofs) != 1 {
		return invalid("exactly one DPoP header is required")
	}
	proof := proofs[0]
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return invalid("not a compact JWS")
	}
	var header struct {
		Typ string          `json:"typ"`
		Alg string          `json:"alg"`
		JWK json.RawMessage `json:"jwk"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return invalid("header: %v", err)
	}
	if header.Typ != "dpop+jwt" {
		return invalid(`typ must be "dpop+jwt"`)
	}
	alg, ok := jwa.LookupSignatureAlgorithm(header.Alg)
	if !ok || !slices.Contains(strings.Fields(dpopAlgs), header.Alg) {
		return invalid("alg %q is not accepted", header.Alg)
	}
	key, err := jwk.ParseKey(header.JWK)
	if err != nil {
		return invalid("jwk: %v", err)
	}
	if private, err := jwk.IsPrivateKey(key); err != nil || private {
		return invalid("jwk must be a public key")
	}
	payload, err := jws.Verify([]byte(proof), jws.WithKey(alg, key))
	if err != nil {
		return invalid("signature: %v", err)
	}
	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return invalid("thumbprint: %v", err)
	}
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(thumb)), []byte(jkt)) != 1 {
		return invalid("the proof key is not the key the token is bound to")
	}

	var claims struct {
		JTI string  `json:"jti"`
		HTM string  `json:"htm"`
		HTU string  `json:"htu"`
		IAT float64 `json:"iat"`
		ATH string  `json:"ath"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return invalid("claims: %v", err)
	}
	switch {
	case claims.JTI == "":
		return invalid("jti is required")
	case claims.HTM != r.Method:
		return invalid("htm does not match the request method")
	case !sameTarget(claims.HTU, v.baseURL+r.URL.Path):
		return invalid("htu does not match the request URL")
	}
	hash := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare([]byte(claims.ATH), []byte(base64.RawURLEncoding.EncodeToString(hash[:]))) != 1 {
		return invalid("ath does not match the access token")
	}
	now := v.now()
	iat := time.Unix(int64(claims.IAT), 0)
	maxAge := v.sc.DPoP.maxAge
	if claims.IAT == 0 || iat.After(now.Add(clockSkew)) || now.Sub(iat) > maxAge+clockSkew {
		return invalid("iat is outside the accepted window")
	}
	fresh, err := v.replay.Remember(r.Context(), "dpop:"+jkt+":"+claims.JTI, iat.Add(maxAge+2*clockSkew))
	if err != nil {
		return fmt.Errorf("recording the DPoP proof: %w", err)
	}
	if !fresh {
		return invalid("the proof has been used before")
	}
	return nil
}

// sameTarget compares a proof's htu with the request URL, ignoring query
// and fragment, with scheme and host case-insensitive and default ports
// dropped (RFC 9449 §4.3, RFC 3986 §6.2.2 and §6.2.3).
func sameTarget(htu, want string) bool {
	a, err1 := url.Parse(htu)
	b, err2 := url.Parse(want)
	if err1 != nil || err2 != nil {
		return false
	}
	norm := func(u *url.URL) string {
		host := strings.ToLower(u.Host)
		scheme := strings.ToLower(u.Scheme)
		host = strings.TrimSuffix(host, map[string]string{"https": ":443", "http": ":80"}[scheme])
		path := u.EscapedPath()
		if path == "" {
			path = "/"
		}
		return scheme + "://" + host + path
	}
	return norm(a) == norm(b)
}

// checkMTLS compares the token's certificate thumbprint with the client
// certificate (RFC 8705 §3).
func (v *Verifier) checkMTLS(r *http.Request, x5t string) error {
	want, err := base64.RawURLEncoding.DecodeString(x5t)
	if err != nil || len(want) != sha256.Size {
		return failure("invalid_token", "cnf x5t#S256 is not a base64url SHA-256 thumbprint")
	}
	got, err := v.clientCertHash(r)
	if err != nil {
		return failure("invalid_token", "client certificate: %v", err)
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return failure("invalid_token", "the client certificate is not the one the token is bound to")
	}
	return nil
}

// clientCertHash is the SHA-256 of the client certificate's DER.
func (v *Verifier) clientCertHash(r *http.Request) ([]byte, error) {
	m := v.sc.MTLS
	if m.Source == MTLSSourceTLS {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			return nil, errors.New("the connection presented none")
		}
		sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
		return sum[:], nil
	}
	value := r.Header.Get(m.Header)
	if value == "" {
		return nil, fmt.Errorf("header %s is absent", m.Header)
	}
	if m.Format == FormatPEM {
		return pemHash(value)
	}
	return xfccHash(value)
}

func pemHash(escaped string) ([]byte, error) {
	text, err := url.QueryUnescape(escaped)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(text))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	return sum[:], nil
}

// xfccHash reads the client certificate's SHA-256 from Envoy's
// X-Forwarded-Client-Cert: the last element (the client of the proxy
// nearest this server), its Hash, else the digest of its Cert.
func xfccHash(value string) ([]byte, error) {
	elements := splitQuoted(value, ',')
	fields := map[string]string{}
	for _, kv := range splitQuoted(elements[len(elements)-1], ';') {
		k, val, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if ok {
			fields[strings.ToLower(k)] = strings.Trim(val, `"`)
		}
	}
	if h := fields["hash"]; h != "" {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != sha256.Size {
			return nil, errors.New("the Hash field is not a hex SHA-256 digest")
		}
		return b, nil
	}
	if c := fields["cert"]; c != "" {
		return pemHash(c)
	}
	return nil, errors.New("X-Forwarded-Client-Cert carries neither Hash nor Cert")
}

// splitQuoted splits s on sep outside double quotes.
func splitQuoted(s string, sep rune) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, c := range s {
		switch {
		case c == '"':
			quoted = !quoted
			cur.WriteRune(c)
		case c == sep && !quoted:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(c)
		}
	}
	return append(out, cur.String())
}

// MemoryReplay is a per-process Replay. It forgets identifiers past their
// expiry; replicas do not share it.
type MemoryReplay struct {
	mu    sync.Mutex
	seen  map[string]time.Time
	sweep time.Time
	now   func() time.Time
}

// NewMemoryReplay returns an empty MemoryReplay.
func NewMemoryReplay() *MemoryReplay {
	return &MemoryReplay{seen: map[string]time.Time{}, now: time.Now}
}

// Remember implements Replay.
func (m *MemoryReplay) Remember(_ context.Context, id string, exp time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if now.Sub(m.sweep) > time.Minute {
		for k, e := range m.seen {
			if now.After(e) {
				delete(m.seen, k)
			}
		}
		m.sweep = now
	}
	if e, ok := m.seen[id]; ok && !now.After(e) {
		return false, nil
	}
	m.seen[id] = exp
	return true, nil
}
