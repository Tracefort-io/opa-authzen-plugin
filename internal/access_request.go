package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars"
	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// This file implements the Policy Decision Point's obligations under the
// AuthZEN Access Request and Approval Profile 1.0 that go beyond discovery
// (see Config.AccessRequestEndpoint and Config.JWKSURI):
//
//   - "Issue a Requestable Denial": a `context.access_request` a policy
//     returns is kept only where the profile allows one, completed with the
//     members the PDP MUST supply, and given denial-binding material —
//     `context.evaluation_id` always, and a PDP-signed `binding_token` when
//     a signing key is configured.
//   - "Verify the Approval at Re-evaluation": a `context.approval` a PEP
//     carries is verified against the trusted Access Request Service keys
//     before the policy sees it, and replaced with what was verified.
//   - "Keys and Metadata": the verification keys for both are served as a
//     JWK Set and advertised as `jwks_uri`.
//
// The Access Request Service itself (submission, tasks, approval workflow)
// is not hosted here; the profile lets a separate service play that role.

const (
	// jwksPath serves the JWK Set advertised as `jwks_uri` when the plugin
	// holds keys of its own.
	jwksPath = "/access/v1/jwks"

	// defaultDenialTTL bounds a requestable-denial hint the policy gave no
	// expiry. The profile asks for a short one, "typically minutes".
	defaultDenialTTL = 10 * time.Minute

	// approvalClockSkew is the tolerance applied when comparing an approval's
	// expiry, produced on the Access Request Service's host, to the local
	// clock. The profile calls 30 seconds typical and above 60 NOT
	// RECOMMENDED ("Time and Clock Skew").
	approvalClockSkew = 30 * time.Second
)

// Re-evaluation denial reason codes the plugin reports on an approval it
// could not use ("Re-evaluation Denials"). The policy decides whether to
// deny; these tell it why the approval does not count.
const (
	reasonApprovalUnverifiable = "approval_unverifiable"
	reasonApprovalExpired      = "approval_expired"
	reasonOutOfScope           = "out_of_scope"
)

// machineryMembers are the Decision Context members the profile defines for
// its own use. They are never authorization-relevant ("Structural
// Comparison"), so they cannot be bound.
var machineryMembers = []string{"access_request", "evaluation_id", "evaluated_at", "reason", "approval"}

// AccessRequestConfig configures requestable-denial issuance and approval
// verification. Every field is optional; with none set the plugin only
// enforces the profile's placement rules on a policy-supplied
// `context.access_request` and assigns it an `evaluation_id`.
type AccessRequestConfig struct {
	// SigningKeyFile is a private JWK (JSON, or PEM) the PDP signs
	// `binding_token` values with. The JWK must name its `alg`; a missing
	// `kid` is assigned from the key's thumbprint. Requires base_url (the
	// token's `iss`) and Audience. An independent Access Request Service —
	// one that does not share the PDP's evaluation state — can only verify
	// a denial through such a token.
	SigningKeyFile string `json:"signing_key_file,omitempty"`
	// Audience is the Access Request Service identifier placed in the
	// `binding_token` `aud` claim, which the service MUST check.
	Audience string `json:"audience,omitempty"`
	// DenialTTL is the lifetime given a requestable-denial hint whose policy
	// set no `expires_at`, as a Go duration. Defaults to 10m.
	DenialTTL string `json:"denial_ttl,omitempty"`
	// BindingContextMembers names the request `context` members that are
	// authorization-relevant: bound into the `binding_token` and compared
	// at approval verification. Empty binds only subject, resource and
	// action.
	BindingContextMembers []string `json:"binding_context_members,omitempty"`
	// ApprovalIssuers lists the Access Request Services whose signed
	// `approval.state` the PDP accepts at re-evaluation. Their keys are
	// published in the PDP's JWK Set, which the profile treats as the PDP's
	// statement that it trusts them. Requires base_url, the audience an
	// `approval.state` must name. Empty leaves `context.approval` to the
	// policy, for deployments that resolve `approval.id` from shared state.
	ApprovalIssuers []ApprovalIssuer `json:"approval_issuers,omitempty"`
	// Service hosts the Access Request Service in the plugin.
	Service ServiceConfig `json:"service,omitempty"`

	signingKey jwk.Key
	signingAlg jwa.SignatureAlgorithm
	signingKID string
	denialTTL  time.Duration
	issuers    map[string]jwk.Set
	publicKeys jwk.Set
}

// ApprovalIssuer is one trusted signer of `approval.state`.
type ApprovalIssuer struct {
	// Issuer is the exact `iss` claim the signer uses.
	Issuer string `json:"issuer"`
	// JWKSFile is a JWK Set of the signer's public keys. Each key must carry
	// `kid` and `alg`.
	JWKSFile string `json:"jwks_file"`
}

// load validates the configuration and reads its key material. It runs from
// Validate, after base_url and jwks_uri are normalized; when the plugin ends
// up holding keys and the operator advertised no jwks_uri, it advertises its
// own.
func (a *AccessRequestConfig) load(cfg *Config) error {
	a.denialTTL = defaultDenialTTL
	if s := strings.TrimSpace(a.DenialTTL); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("denial_ttl %q: %w", a.DenialTTL, err)
		}
		if d <= 0 {
			return fmt.Errorf("denial_ttl %q must be positive", a.DenialTTL)
		}
		a.denialTTL = d
	}

	seen := map[string]bool{}
	for i, m := range a.BindingContextMembers {
		m = strings.TrimSpace(m)
		switch {
		case m == "":
			return fmt.Errorf("binding_context_members[%d] must not be empty", i)
		case slices.Contains(machineryMembers, m):
			return fmt.Errorf("binding_context_members[%d] %q is a profile member and cannot be authorization-relevant", i, m)
		case seen[m]:
			return fmt.Errorf("binding_context_members[%d] %q is listed twice", i, m)
		}
		seen[m] = true
		a.BindingContextMembers[i] = m
	}

	served := jwk.NewSet()
	kids := map[string]bool{}
	addServed := func(k jwk.Key, kid string) error {
		if kids[kid] {
			return fmt.Errorf("kid %q appears in more than one key; kids must be unique across the served JWK Set", kid)
		}
		kids[kid] = true
		return served.AddKey(k)
	}

	a.Audience = strings.TrimSpace(a.Audience)
	if a.SigningKeyFile != "" {
		if cfg.BaseURL == "" {
			return fmt.Errorf("signing_key_file requires base_url, the binding_token issuer")
		}
		if a.Audience == "" {
			return fmt.Errorf("signing_key_file requires audience, the Access Request Service identifier")
		}
		key, alg, kid, err := loadSigningKey(a.SigningKeyFile)
		if err != nil {
			return fmt.Errorf("signing_key_file: %w", err)
		}
		pub, err := key.PublicKey()
		if err != nil {
			return fmt.Errorf("signing_key_file: deriving public key: %w", err)
		}
		if err := pub.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
			return fmt.Errorf("signing_key_file: %w", err)
		}
		if err := addServed(pub, kid); err != nil {
			return fmt.Errorf("signing_key_file: %w", err)
		}
		a.signingKey, a.signingAlg, a.signingKID = key, alg, kid
	} else if a.Audience != "" {
		return fmt.Errorf("audience is only used with signing_key_file")
	}

	if len(a.ApprovalIssuers) > 0 {
		if cfg.BaseURL == "" {
			return fmt.Errorf("approval_issuers requires base_url, the audience an approval.state must name")
		}
		a.issuers = map[string]jwk.Set{}
		for i, iss := range a.ApprovalIssuers {
			name := strings.TrimSpace(iss.Issuer)
			if name == "" {
				return fmt.Errorf("approval_issuers[%d].issuer must not be empty", i)
			}
			if _, dup := a.issuers[name]; dup {
				return fmt.Errorf("approval_issuers[%d].issuer %q is listed twice", i, name)
			}
			set, err := loadIssuerKeys(iss.JWKSFile)
			if err != nil {
				return fmt.Errorf("approval_issuers[%d] (%s): %w", i, name, err)
			}
			for j := range set.Len() {
				k, _ := set.Key(j)
				kid, _ := k.KeyID()
				if err := addServed(k, kid); err != nil {
					return fmt.Errorf("approval_issuers[%d] (%s): %w", i, name, err)
				}
			}
			a.ApprovalIssuers[i].Issuer = name
			a.issuers[name] = set
		}
	}

	if served.Len() > 0 {
		a.publicKeys = served
		if cfg.JWKSURI == "" {
			cfg.JWKSURI = cfg.BaseURL + jwksPath
		}
	}
	return a.Service.load(cfg, a)
}

// loadSigningKey reads the PDP's private signing key.
func loadSigningKey(path string) (jwk.Key, jwa.SignatureAlgorithm, string, error) {
	var none jwa.SignatureAlgorithm
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, none, "", err
	}
	key, err := jwk.ParseKey(data)
	if err != nil {
		if key, err = jwk.ParseKey(data, jwk.WithPEM(true)); err != nil {
			return nil, none, "", fmt.Errorf("not a JWK or PEM key: %w", err)
		}
	}
	// A symmetric key cannot be published for an independent verifier.
	if key.KeyType() == jwa.OctetSeq() {
		return nil, none, "", fmt.Errorf("must be an asymmetric key, not %s", key.KeyType())
	}
	if private, err := jwk.IsPrivateKey(key); err != nil || !private {
		return nil, none, "", fmt.Errorf("must be a private key")
	}
	ka, ok := key.Algorithm()
	if !ok {
		return nil, none, "", fmt.Errorf("the JWK must name its signing algorithm in \"alg\"")
	}
	alg, ok := jwa.LookupSignatureAlgorithm(ka.String())
	if !ok || alg == jwa.NoSignature() {
		return nil, none, "", fmt.Errorf("alg %q is not a signature algorithm", ka.String())
	}
	kid, ok := key.KeyID()
	if !ok || kid == "" {
		if err := jwk.AssignKeyID(key); err != nil {
			return nil, none, "", fmt.Errorf("assigning kid: %w", err)
		}
		kid, _ = key.KeyID()
	}
	return key, alg, kid, nil
}

// loadIssuerKeys reads one Access Request Service's public keys.
func loadIssuerKeys(path string) (jwk.Set, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("jwks_file must not be empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	set, err := jwk.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("jwks_file: %w", err)
	}
	if set.Len() == 0 {
		return nil, fmt.Errorf("jwks_file holds no keys")
	}
	for i := range set.Len() {
		k, _ := set.Key(i)
		if private, err := jwk.IsPrivateKey(k); err != nil || private {
			return nil, fmt.Errorf("jwks_file key %d must be a public key", i)
		}
		if k.KeyType() == jwa.OctetSeq() {
			return nil, fmt.Errorf("jwks_file key %d must be an asymmetric key", i)
		}
		if kid, ok := k.KeyID(); !ok || kid == "" {
			return nil, fmt.Errorf("jwks_file key %d has no kid", i)
		}
		if _, ok := k.Algorithm(); !ok {
			return nil, fmt.Errorf("jwks_file key %d has no alg", i)
		}
	}
	return set, nil
}

// handleJWKS serves the PDP's JWK Set ("Keys and Metadata"): the public half
// of the binding_token signing key and the keys of every trusted
// approval.state signer.
func (p *AuthZenPlugin) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		w.Header().Set("X-Request-ID", reqID)
	}
	p.mu.RLock()
	stopped := p.stopped
	set := p.cfg.AccessRequest.publicKeys
	p.mu.RUnlock()
	if stopped {
		jsonError(w, "plugin is shutting down", http.StatusServiceUnavailable)
		return
	}
	if set == nil {
		jsonError(w, "no keys are configured", http.StatusNotFound)
		return
	}
	body, err := json.Marshal(set)
	if err != nil {
		p.logger.Error("AuthZEN jwks: failed to encode key set: %v", err)
		jsonError(w, "failed to encode key set", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", metadataCacheControl)
	_, _ = w.Write(body)
}

// finalizeDecisionContext applies the profile rules that bind the PDP to the
// object the decision_context rule returned, in place: obligation shape
// (Obligations Profile) and the requestable-denial and re-evaluation members
// (Access Request and Approval Profile).
func (p *AuthZenPlugin) finalizeDecisionContext(obj, input map[string]any, decision bool, snap *evalConfig) error {
	if v, ok := obj["obligations"]; ok {
		if err := validateObligations(v, snap.obligations); err != nil {
			return err
		}
	}
	if err := p.finalizeAccessRequest(obj, input, decision, snap); err != nil {
		return err
	}
	if decision {
		return nil
	}
	return validateReevaluationDenial(obj)
}

// finalizeAccessRequest enforces "Issue a Requestable Denial" on a
// policy-supplied `context.access_request`.
func (p *AuthZenPlugin) finalizeAccessRequest(obj, input map[string]any, decision bool, snap *evalConfig) error {
	raw, present := obj["access_request"]
	if !present {
		return nil
	}
	ar, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("access_request must be an object; got %T", raw)
	}
	// A requestable denial is a denial; on a permit the hint means nothing,
	// and a PEP must never act on it.
	if decision {
		delete(obj, "access_request")
		p.logger.Warn("AuthZEN: dropped context.access_request returned on a permit")
		return nil
	}
	if v, ok := ar["endpoint"]; ok {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("access_request.endpoint must be a string")
		}
		if u, err := url.Parse(s); err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("access_request.endpoint %q must be an https URI", s)
		}
	} else if snap.accessRequestEndpoint == "" {
		// "MUST NOT include context.access_request unless ... an Access
		// Request Endpoint is available to process the request."
		delete(obj, "access_request")
		p.logger.Warn("AuthZEN: dropped context.access_request: no access_request_endpoint is configured and the hint names no endpoint")
		return nil
	}

	now := p.now().UTC()
	ac := &snap.accessRequest

	var expires time.Time
	if v, ok := ar["expires_at"]; ok {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("access_request.expires_at must be an RFC 3339 string")
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return fmt.Errorf("access_request.expires_at %q is not an RFC 3339 timestamp", s)
		}
		if !t.After(now) {
			return fmt.Errorf("access_request.expires_at %q is not in the future", s)
		}
		expires = t
	} else {
		// The member is REQUIRED; supply the configured lifetime.
		ttl := ac.denialTTL
		if ttl <= 0 {
			ttl = defaultDenialTTL
		}
		expires = now.Add(ttl).Truncate(time.Second)
		ar["expires_at"] = expires.Format(time.RFC3339)
	}

	// Denial-binding material by reference. The PDP SHOULD return a stable
	// evaluation identifier, and MUST where no binding_token is issued.
	evalID, err := ensureStringMember(obj, "evaluation_id", newEvaluationID)
	if err != nil {
		return err
	}
	if _, err := ensureStringMember(obj, "evaluated_at", func() string { return now.Format(time.RFC3339) }); err != nil {
		return err
	}

	if ac.signingKey != nil {
		if _, has := ar["binding_token"]; !has {
			token, err := signBindingToken(ac, snap.baseURL, input, evalID, ar["expires_at"].(string), expires, now)
			if err != nil {
				return fmt.Errorf("signing binding_token: %w", err)
			}
			ar["binding_token"] = token
		}
	}
	return nil
}

// ensureStringMember returns obj[name], setting it from gen when absent.
func ensureStringMember(obj map[string]any, name string, gen func() string) (string, error) {
	v, ok := obj[name]
	if !ok {
		s := gen()
		obj[name] = s
		return s, nil
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("%s must be a non-empty string", name)
	}
	return s, nil
}

// newEvaluationID returns an evaluation identifier. UUIDv7 is unique within
// the PDP's namespace and sorts by issue time, which the profile suggests
// ("for example, ULIDs or UUIDs").
func newEvaluationID() string {
	if id, err := uuid.NewV7(); err == nil {
		return "eval_" + id.String()
	}
	return "eval_" + uuid.NewString()
}

// signBindingToken issues the self-contained binding_token of "Denial
// Binding Claims", inline form: it carries the denied Subject, Resource,
// Action and authorization-relevant Context by value so an independent
// Access Request Service can verify a submission offline.
func signBindingToken(ac *AccessRequestConfig, issuer string, input map[string]any, evalID, expiresAt string, expires, now time.Time) (string, error) {
	members := ac.BindingContextMembers
	if members == nil {
		members = []string{}
	}
	claims := map[string]any{
		"iss":                     issuer,
		"aud":                     ac.Audience,
		"iat":                     now.Unix(),
		"exp":                     expires.Unix(),
		"jti":                     uuid.NewString(),
		"denial_expires_at":       expiresAt,
		"evaluation_id":           evalID,
		"binding_context_members": members,
		"subject":                 ars.WithoutActor(input["subject"]),
		"resource":                input["resource"],
		"action":                  input["action"],
		"context":                 ars.RelevantContext(requestContext(input), members),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	hdr := jws.NewHeaders()
	if err := hdr.Set(jws.KeyIDKey, ac.signingKID); err != nil {
		return "", err
	}
	if err := hdr.Set(jws.TypeKey, "JWT"); err != nil {
		return "", err
	}
	out, err := jws.Sign(payload, jws.WithKey(ac.signingAlg, ac.signingKey, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// validateReevaluationDenial checks the members a PDP uses to direct the PEP
// after a denied re-evaluation ("Re-evaluation Denials").
func validateReevaluationDenial(obj map[string]any) error {
	if v, ok := obj["next_action"]; ok {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("next_action must be a string")
		}
		// "When next_action is request, the PDP MUST also include a fresh
		// context.access_request."
		if s == "request" {
			if _, ok := obj["access_request"]; !ok {
				return fmt.Errorf("next_action \"request\" requires a context.access_request the PEP can submit against")
			}
		}
	}
	if v, ok := obj["retry_after"]; ok {
		if n, ok := nonNegativeInteger(v); !ok || n < 0 {
			return fmt.Errorf("retry_after must be a non-negative integer number of seconds")
		}
	}
	return nil
}

// nonNegativeInteger reads an integer from a policy result, where OPA
// renders numbers as json.Number.
func nonNegativeInteger(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case float64:
		if n != float64(int64(n)) {
			return 0, false
		}
		return int64(n), true
	case int:
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}

// verifyApproval implements "Approval Verification" for a PDP configured
// with trusted approval.state signers. The `context.approval` the PEP
// carried is replaced, before any rule runs, by what the plugin could
// establish about it, so a policy reads only verified values:
//
//	{"id", "verified": true, "issuer", "approved_until", ["approved_at"], ["task_id"]}
//	{["id"], "verified": false, "reason": "approval_unverifiable" | "approval_expired" | "out_of_scope"}
//
// A PEP cannot assert `verified` itself: the member is always overwritten.
//
// With the Access Request Service hosted in the plugin, approvals are
// resolved by `approval.id` in its store, which also answers the current
// status the profile requires checking: a revoked approval is reported as
// approval_expired. An approval the store does not hold falls back to the
// signed approval.state path when approval_issuers is configured. Without
// the service, a signed state cannot carry revocation, so a policy checks it
// against its own data, keyed by the verified `id`.
//
// An error is returned only when the store cannot be read; the evaluation
// then fails rather than reporting a valid approval as unverifiable.
func (p *AuthZenPlugin) verifyApproval(ctx context.Context, input map[string]any, snap *evalConfig) error {
	if len(snap.accessRequest.issuers) == 0 && snap.approvals == nil {
		return nil
	}
	reqCtx := requestContext(input)
	raw, present := reqCtx["approval"]
	if !present {
		return nil
	}
	now := p.now().UTC()
	var verified map[string]any
	var aerr *approvalError
	if snap.approvals != nil {
		found, v, e, err := lookupApproval(ctx, snap.approvals, raw, input, snap, now)
		if err != nil {
			return err
		}
		if found {
			verified, aerr = v, e
		}
	}
	if verified == nil {
		if len(snap.accessRequest.issuers) > 0 {
			verified, aerr = checkApproval(raw, input, snap, now)
		} else {
			verified, aerr = unverifiable(raw, errors.New("approval is not held by the Access Request Service"))
		}
	}
	if aerr != nil {
		p.logger.WithFields(map[string]any{"reason": aerr.reason, "error": aerr.err}).Debug("AuthZEN: approval not accepted")
	}
	reqCtx["approval"] = verified
	return nil
}

// requestContext returns the input's `context` object, or nil.
func requestContext(input map[string]any) map[string]any {
	ctx, _ := input["context"].(map[string]any)
	return ctx
}

func unverifiable(raw any, err error) (map[string]any, *approvalError) {
	out := map[string]any{"verified": false, "reason": reasonApprovalUnverifiable}
	if a, ok := raw.(map[string]any); ok {
		if id, ok := a["id"].(string); ok && id != "" {
			out["id"] = id
		}
	}
	return out, &approvalError{reason: reasonApprovalUnverifiable, err: err}
}

// lookupApproval resolves an approval in the Access Request Service store
// ("Approval Reference by Lookup", "Current Approval Status", "Approval
// Scope"). found is false when the store holds no such approval.
func lookupApproval(ctx context.Context, st store.Store, raw any, input map[string]any, snap *evalConfig, now time.Time) (bool, map[string]any, *approvalError, error) {
	approval, ok := raw.(map[string]any)
	if !ok {
		v, e := unverifiable(raw, errors.New("approval is not an object"))
		return true, v, e, nil
	}
	id, _ := approval["id"].(string)
	if id == "" {
		v, e := unverifiable(raw, errors.New("approval.id is missing"))
		return true, v, e, nil
	}
	a, err := st.GetApproval(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil, nil, nil
	}
	if err != nil {
		return false, nil, nil, fmt.Errorf("looking up approval %s: %w", id, err)
	}
	fail := func(reason string, err error) (bool, map[string]any, *approvalError, error) {
		return true, map[string]any{"id": id, "verified": false, "reason": reason}, &approvalError{reason: reason, err: err}, nil
	}
	if a.RevokedAt != nil {
		return fail(reasonApprovalExpired, errors.New("approval was revoked"))
	}
	if now.After(a.ApprovedUntil.Add(approvalClockSkew)) {
		return fail(reasonApprovalExpired, errors.New("approved_until has passed"))
	}
	switch {
	case !ars.SameBinding(ars.WithoutActor(a.Subject), ars.WithoutActor(input["subject"])):
		return fail(reasonOutOfScope, errors.New("subject differs from the approved subject"))
	case !ars.SameBinding(a.Resource, input["resource"]):
		return fail(reasonOutOfScope, errors.New("resource differs from the approved resource"))
	case !ars.SameBinding(a.Action, input["action"]):
		return fail(reasonOutOfScope, errors.New("action differs from the approved action"))
	case !ars.SameBinding(nonNil(a.Context), ars.RelevantContext(requestContext(input), a.BindingContextMembers)):
		return fail(reasonOutOfScope, errors.New("authorization-relevant context differs from the approved context"))
	}
	return true, map[string]any{
		"id":             id,
		"verified":       true,
		"issuer":         snap.baseURL,
		"task_id":        a.TaskID,
		"approved_at":    a.ApprovedAt.UTC().Format(time.RFC3339),
		"approved_until": a.ApprovedUntil.UTC().Format(time.RFC3339),
	}, nil, nil
}

func nonNil(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// approvalError carries the reason code reported to the policy and the
// detail logged for the operator.
type approvalError struct {
	reason string
	err    error
}

func checkApproval(raw any, input map[string]any, snap *evalConfig, now time.Time) (map[string]any, *approvalError) {
	out := map[string]any{"verified": false}
	fail := func(reason string, err error) (map[string]any, *approvalError) {
		out["reason"] = reason
		return out, &approvalError{reason: reason, err: err}
	}

	approval, ok := raw.(map[string]any)
	if !ok {
		return fail(reasonApprovalUnverifiable, errors.New("approval is not an object"))
	}
	id, _ := approval["id"].(string)
	if id == "" {
		return fail(reasonApprovalUnverifiable, errors.New("approval.id is missing"))
	}
	out["id"] = id

	state, _ := approval["state"].(string)
	parts := strings.Split(state, ".")
	if len(parts) != 3 {
		return fail(reasonApprovalUnverifiable, errors.New("approval.state is not a JWS compact serialization"))
	}
	var unverified struct {
		Iss string `json:"iss"`
	}
	if err := decodeJWTSegment(parts[1], &unverified); err != nil {
		return fail(reasonApprovalUnverifiable, fmt.Errorf("approval.state claims: %w", err))
	}
	keys, ok := snap.accessRequest.issuers[unverified.Iss]
	if !ok {
		return fail(reasonApprovalUnverifiable, fmt.Errorf("approval.state issuer %q is not trusted", unverified.Iss))
	}
	payload, err := jws.Verify([]byte(state), jws.WithKeySet(keys))
	if err != nil {
		return fail(reasonApprovalUnverifiable, fmt.Errorf("approval.state signature: %w", err))
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fail(reasonApprovalUnverifiable, fmt.Errorf("approval.state claims: %w", err))
	}

	// "MUST carry an aud ... identifying the verifying PDP, which the PDP
	// MUST verify."
	if !audienceIncludes(claims["aud"], snap.baseURL) {
		return fail(reasonApprovalUnverifiable, fmt.Errorf("approval.state aud does not name %s", snap.baseURL))
	}
	// "When both approval.id and an integrity-protected approval.state are
	// present and approval.state carries its own approval identifier, the
	// PDP MUST verify that the two identifiers match."
	if claimed, _ := claims["approval_id"].(string); claimed != id {
		return fail(reasonApprovalUnverifiable, fmt.Errorf("approval.state approval_id %q does not match approval.id %q", claimed, id))
	}
	untilStr, _ := claims["approved_until"].(string)
	until, err := time.Parse(time.RFC3339, untilStr)
	if err != nil {
		return fail(reasonApprovalUnverifiable, fmt.Errorf("approval.state approved_until %q is not an RFC 3339 timestamp", untilStr))
	}
	if now.After(until.Add(approvalClockSkew)) {
		return fail(reasonApprovalExpired, fmt.Errorf("approved_until %s has passed", untilStr))
	}
	if exp, ok := claims["exp"].(float64); ok && now.After(time.Unix(int64(exp), 0).Add(approvalClockSkew)) {
		return fail(reasonApprovalExpired, errors.New("approval.state has expired"))
	}

	// Exact-match approval scope: the default the profile requires two
	// independent implementations to agree on ("Approval Scope").
	for _, name := range []string{"subject", "resource", "action"} {
		if _, ok := claims[name].(map[string]any); !ok {
			return fail(reasonApprovalUnverifiable, fmt.Errorf("approval.state carries no %s binding", name))
		}
	}
	members, _ := stringArray(claims["binding_context_members"])
	boundCtx, _ := claims["context"].(map[string]any)
	if boundCtx == nil {
		boundCtx = map[string]any{}
	}
	switch {
	case !ars.SameBinding(ars.WithoutActor(claims["subject"]), ars.WithoutActor(input["subject"])):
		return fail(reasonOutOfScope, errors.New("subject differs from the approved subject"))
	case !ars.SameBinding(claims["resource"], input["resource"]):
		return fail(reasonOutOfScope, errors.New("resource differs from the approved resource"))
	case !ars.SameBinding(claims["action"], input["action"]):
		return fail(reasonOutOfScope, errors.New("action differs from the approved action"))
	case !ars.SameBinding(boundCtx, ars.RelevantContext(requestContext(input), members)):
		return fail(reasonOutOfScope, errors.New("authorization-relevant context differs from the approved context"))
	}

	verified := map[string]any{
		"id":             id,
		"verified":       true,
		"issuer":         unverified.Iss,
		"approved_until": untilStr,
	}
	for _, name := range []string{"approved_at", "task_id"} {
		if s, ok := claims[name].(string); ok && s != "" {
			verified[name] = s
		}
	}
	return verified, nil
}

// audienceIncludes reports whether a JWT `aud` claim, a string or an array
// of strings (RFC 7519 Section 4.1.3), names want.
func audienceIncludes(aud any, want string) bool {
	if s, ok := aud.(string); ok {
		return s == want
	}
	list, ok := stringArray(aud)
	return ok && slices.Contains(list, want)
}
