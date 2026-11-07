package internal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/authn"
)

// PEP authentication on the AuthZEN API (design §19.2). The Authorization
// API says the PDP SHOULD authenticate the calling PEP and recommends OAuth
// 2.0; with pep_auth, the evaluation and search endpoints require a token
// from a listed issuer, bearer or sender-constrained.

// build makes the AuthConfig's verifier: its issuers and, when configured,
// proof of possession with DPoP proofs checked against baseURL and recorded
// in replay.
func (a *AuthConfig) build(name, baseURL string, replay authn.Replay) (*authn.Verifier, error) {
	v, err := authn.NewVerifier(a.Issuers, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if a.SenderConstraint != nil {
		if a.SenderConstraint.DPoP != nil && a.SenderConstraint.DPoP.Enabled && baseURL == "" {
			return nil, fmt.Errorf("%s: sender_constraint.dpop requires base_url, from which proofs' htu is checked", name)
		}
		if err := v.WithSenderConstraint(a.SenderConstraint, baseURL, replay); err != nil {
			return nil, fmt.Errorf("%s: sender_constraint: %w", name, err)
		}
	}
	return v, nil
}

// loadPEPAuth builds the AuthZEN API's verifier. DPoP proofs are
// remembered per replica, keeping the database off the evaluation path.
func (c *Config) loadPEPAuth() error {
	if c.PEPAuth == nil {
		return nil
	}
	v, err := c.PEPAuth.build("pep_auth", c.BaseURL, authn.NewMemoryReplay())
	if err != nil {
		return err
	}
	c.PEPAuth.verifier = v
	return nil
}

type pepKey struct{}

// withPEPAuth requires an authenticated PEP for h when pep_auth is
// configured, answering 401 with the verifier's WWW-Authenticate
// challenges (Section 12.2) otherwise. The identity reaches policies as
// input.pep (addPEP).
func (p *AuthZenPlugin) withPEPAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.mu.RLock()
		var v *authn.Verifier
		if p.cfg.PEPAuth != nil {
			v = p.cfg.PEPAuth.verifier
		}
		realm := p.cfg.BaseURL
		p.mu.RUnlock()
		if v == nil {
			h(w, r)
			return
		}
		id, err := v.Authenticate(r)
		if err != nil {
			if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
				w.Header().Set("X-Request-ID", reqID)
			}
			if !errors.Is(err, authn.ErrUnauthenticated) {
				p.logger.Error("AuthZEN PEP authentication: %v", err)
				jsonError(w, "authentication failed", http.StatusInternalServerError)
				return
			}
			p.metrics.Count(r.Context(), metricAuthFailures, map[string]string{"api": "authzen", "reason": authn.Reason(err)})
			if realm == "" {
				realm = "authzen"
			}
			for _, c := range v.Challenges(realm, err) {
				w.Header().Add("WWW-Authenticate", c)
			}
			jsonError(w, "a valid access token is required", http.StatusUnauthorized)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), pepKey{}, id)))
	}
}

// addPEP gives policies the authenticated PEP as input.pep. Without
// pep_auth there is none, and the input is unchanged.
func addPEP(ctx context.Context, input map[string]any) {
	id, ok := ctx.Value(pepKey{}).(*authn.Identity)
	if !ok {
		return
	}
	input["pep"] = map[string]any{"iss": id.Iss, "sub": id.Sub, "client_id": id.ClientID, "claims": id.Claims}
}

// replayRef is the service APIs' DPoP replay store: the service's store,
// shared by every replica, once it is open.
type replayRef struct {
	mu sync.RWMutex
	r  authn.Replay
}

func (x *replayRef) set(r authn.Replay) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.r = r
}

// Remember implements authn.Replay.
func (x *replayRef) Remember(ctx context.Context, id string, exp time.Time) (bool, error) {
	x.mu.RLock()
	r := x.r
	x.mu.RUnlock()
	if r == nil {
		return false, errors.New("the access request service store is not open")
	}
	return r.Remember(ctx, id, exp)
}

// storeReplay records DPoP proof identifiers in the service's seen_jti
// table.
type storeReplay struct {
	remember func(ctx context.Context, id string, exp time.Time) (bool, error)
}

func (s storeReplay) Remember(ctx context.Context, id string, exp time.Time) (bool, error) {
	return s.remember(ctx, id, exp)
}
