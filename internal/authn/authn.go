// Package authn validates OAuth 2.0 access tokens issued as JWTs by
// configured issuers, for the Access Request Service, approver and AuthZEN
// APIs: bearer tokens (RFC 6750) and sender-constrained tokens, DPoP
// (RFC 9449) and certificate-bound (RFC 8705), see bound.go.
//
// A token is accepted when its signature verifies against a key from its
// issuer's JWK Set and its `iss`, `aud`, `exp` and `nbf` claims check out.
// The caller is identified by the (`iss`, `sub`) pair, which OpenID Connect
// Core §2 makes stable and never reassigned within an issuer; delegation is
// read from the RFC 8693 `act` claim.
package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

const (
	// clockSkew tolerates small differences between the issuer's clock and
	// ours when checking exp and nbf.
	clockSkew = 30 * time.Second
	// jwksMaxAge is how long a fetched JWK Set is used before refetching.
	jwksMaxAge = 10 * time.Minute
	// jwksMinRefresh bounds refetches triggered by an unknown kid, so a
	// stream of forged tokens cannot turn into a stream of fetches.
	jwksMinRefresh = 30 * time.Second
	maxJWKSBytes   = 1 << 20
)

// ErrUnauthenticated is wrapped by every rejection, so callers can answer
// 401 without inspecting the reason.
var ErrUnauthenticated = errors.New("unauthenticated")

// Issuer is one trusted token issuer.
type Issuer struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	JWKSURI  string `json:"jwks_uri"`
}

// Identity is an authenticated caller.
type Identity struct {
	Iss      string
	Sub      string
	ClientID string
	// Act is the RFC 8693 actor claim, when the token carries one.
	Act    map[string]any
	Claims map[string]any
}

// Key returns the identity as one string, for scoping idempotency keys and
// for audit records.
func (i *Identity) Key() string { return i.Iss + "|" + i.Sub }

// Verifier validates tokens from a fixed set of issuers: bearer tokens and,
// with WithSenderConstraint, DPoP and certificate-bound tokens.
type Verifier struct {
	issuers map[string]*issuerKeys
	client  *http.Client
	now     func() time.Time
	sc      *SenderConstraint
	baseURL string
	replay  Replay
}

type issuerKeys struct {
	cfg       Issuer
	mu        sync.Mutex
	set       jwk.Set
	fetchedAt time.Time
}

// NewVerifier returns a Verifier for issuers. Keys are fetched lazily.
func NewVerifier(issuers []Issuer, client *http.Client) (*Verifier, error) {
	if len(issuers) == 0 {
		return nil, errors.New("at least one issuer is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	v := &Verifier{issuers: map[string]*issuerKeys{}, client: client, now: time.Now}
	for i, iss := range issuers {
		iss.Issuer = strings.TrimSpace(iss.Issuer)
		iss.Audience = strings.TrimSpace(iss.Audience)
		iss.JWKSURI = strings.TrimSpace(iss.JWKSURI)
		switch {
		case iss.Issuer == "":
			return nil, fmt.Errorf("issuers[%d].issuer must not be empty", i)
		case iss.Audience == "":
			return nil, fmt.Errorf("issuers[%d].audience must not be empty", i)
		case !strings.HasPrefix(iss.JWKSURI, "https://") && !strings.HasPrefix(iss.JWKSURI, "http://"):
			return nil, fmt.Errorf("issuers[%d].jwks_uri must be an http(s) URL", i)
		}
		if _, dup := v.issuers[iss.Issuer]; dup {
			return nil, fmt.Errorf("issuers[%d].issuer %q is listed twice", i, iss.Issuer)
		}
		v.issuers[iss.Issuer] = &issuerKeys{cfg: iss}
	}
	return v, nil
}

// Authenticate validates the request's token: `Bearer`, or `DPoP` with a
// proof when DPoP is enabled. A token bound in `cnf` is accepted only with
// proof of possession of its key.
func (v *Verifier) Authenticate(r *http.Request) (*Identity, error) {
	auth := r.Header.Get("Authorization")
	scheme, token, ok := strings.Cut(auth, " ")
	scheme, token = strings.ToLower(scheme), strings.TrimSpace(token)
	switch {
	case !ok || token == "":
		return nil, &Error{Reason: "missing token"}
	case scheme == "dpop" && !v.sc.dpopEnabled():
		return nil, failure("invalid_request", "the DPoP scheme is not accepted")
	case scheme != "bearer" && scheme != "dpop":
		return nil, &Error{Reason: "unsupported authorization scheme"}
	}
	id, err := v.verify(r.Context(), token)
	if err != nil {
		return nil, err
	}
	if err := v.bind(r, scheme, token, id.Claims); err != nil {
		return nil, err
	}
	return id, nil
}

// Verify validates one compact JWT used as a bearer token. A
// sender-constrained token is refused: without the request, possession of
// its key cannot be proven.
func (v *Verifier) Verify(ctx context.Context, token string) (*Identity, error) {
	id, err := v.verify(ctx, token)
	if err != nil {
		return nil, err
	}
	if _, ok := id.Claims["cnf"]; ok {
		return nil, failure("invalid_token", "sender-constrained tokens need proof of possession")
	}
	return id, nil
}

// verify checks a JWT's signature and claims, leaving `cnf` to the caller.
func (v *Verifier) verify(ctx context.Context, token string) (*Identity, error) {
	fail := func(format string, args ...any) (*Identity, error) {
		return nil, failure("invalid_token", format, args...)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fail("not a compact JWS")
	}
	var header struct {
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return fail("header: %v", err)
	}
	var unverified struct {
		Iss string `json:"iss"`
	}
	if err := decodeSegment(parts[1], &unverified); err != nil {
		return fail("claims: %v", err)
	}
	ik, ok := v.issuers[unverified.Iss]
	if !ok {
		return fail("issuer %q is not trusted", unverified.Iss)
	}
	set, err := ik.keys(ctx, v.client, v.now(), header.Kid)
	if err != nil {
		return fail("issuer keys: %v", err)
	}
	// The key's type pins the algorithm family; a key without "alg" is
	// matched to the header's algorithm only if the key can produce it.
	payload, err := jws.Verify([]byte(token), jws.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		return fail("signature: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fail("claims: %v", err)
	}

	now := v.now()
	if iss, _ := claims["iss"].(string); iss != ik.cfg.Issuer {
		return fail("iss does not match")
	}
	if !audienceIncludes(claims["aud"], ik.cfg.Audience) {
		return fail("aud does not include %q", ik.cfg.Audience)
	}
	exp, ok := numericDate(claims["exp"])
	if !ok {
		return fail("exp is required")
	}
	if now.After(exp.Add(clockSkew)) {
		return fail("token has expired")
	}
	if nbf, ok := numericDate(claims["nbf"]); ok && now.Add(clockSkew).Before(nbf) {
		return fail("token is not yet valid")
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return fail("sub is required")
	}
	id := &Identity{Iss: ik.cfg.Issuer, Sub: sub, Claims: claims}
	if c, _ := claims["client_id"].(string); c != "" {
		id.ClientID = c
	} else if c, _ := claims["azp"].(string); c != "" {
		id.ClientID = c
	}
	if act, ok := claims["act"].(map[string]any); ok {
		id.Act = act
	}
	return id, nil
}

// keys returns the issuer's JWK Set, fetching it when absent, stale, or
// missing kid (bounded by jwksMinRefresh).
func (ik *issuerKeys) keys(ctx context.Context, client *http.Client, now time.Time, kid string) (jwk.Set, error) {
	ik.mu.Lock()
	defer ik.mu.Unlock()
	stale := ik.set == nil || now.Sub(ik.fetchedAt) > jwksMaxAge
	if !stale && kid != "" {
		if _, ok := ik.set.LookupKeyID(kid); !ok && now.Sub(ik.fetchedAt) > jwksMinRefresh {
			stale = true
		}
	}
	if stale {
		set, err := fetchJWKS(ctx, client, ik.cfg.JWKSURI)
		if err != nil {
			if ik.set != nil {
				// Keep serving the last good set through a fetch failure.
				return ik.set, nil
			}
			return nil, err
		}
		ik.set, ik.fetchedAt = set, now
	}
	return ik.set, nil
}

// RemoteKeys is a JWK Set fetched from a URL and cached, refreshed as
// token issuers' keys are: after jwksMaxAge, or on an unknown kid at most
// every jwksMinRefresh, keeping the last good set through a failed fetch.
type RemoteKeys struct {
	ik     issuerKeys
	client *http.Client
	now    func() time.Time
}

// NewRemoteKeys returns the key set published at uri, fetched lazily.
func NewRemoteKeys(uri string, client *http.Client) (*RemoteKeys, error) {
	uri = strings.TrimSpace(uri)
	if !strings.HasPrefix(uri, "https://") && !strings.HasPrefix(uri, "http://") {
		return nil, fmt.Errorf("jwks_uri %q must be an http(s) URL", uri)
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &RemoteKeys{ik: issuerKeys{cfg: Issuer{JWKSURI: uri}}, client: client, now: time.Now}, nil
}

// Keys returns the current set, refetching it when stale or when it lacks
// kid.
func (r *RemoteKeys) Keys(ctx context.Context, kid string) (jwk.Set, error) {
	return r.ik.keys(ctx, r.client, r.now(), kid)
}

func fetchJWKS(ctx context.Context, client *http.Client, uri string) (jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", uri, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return nil, err
	}
	return jwk.Parse(body)
}

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func audienceIncludes(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		return slices.ContainsFunc(a, func(v any) bool { s, _ := v.(string); return s == want })
	}
	return false
}

func numericDate(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}
