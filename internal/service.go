package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars"
	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// This file runs the Access Request Service (access_request.service) inside
// the plugin: it opens the shared store at Start, serves the service's
// routes, and closes the store at Stop.

func openPostgres(ctx context.Context, s *ServiceConfig) (store.Store, error) {
	return store.OpenPostgres(ctx, s.dsn, s.Database.Schema, s.Database.MaxConns)
}

// pdpCrypto is the PDP's binding_token signing key as the service uses it:
// to verify the tokens this PDP issued, and to sign approval.state.
type pdpCrypto struct{ ac *AccessRequestConfig }

func (c pdpCrypto) VerifyBindingToken(token string) (map[string]any, error) {
	pub, err := c.ac.signingKey.PublicKey()
	if err != nil {
		return nil, err
	}
	payload, err := jws.Verify([]byte(token), jws.WithKey(c.ac.signingAlg, pub))
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (c pdpCrypto) SignApprovalState(claims map[string]any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	hdr := jws.NewHeaders()
	if err := hdr.Set(jws.KeyIDKey, c.ac.signingKID); err != nil {
		return "", err
	}
	if err := hdr.Set(jws.TypeKey, "JWT"); err != nil {
		return "", err
	}
	out, err := jws.Sign(payload, jws.WithKey(c.ac.signingAlg, c.ac.signingKey, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// registerServiceRoutes adds the service's routes to OPA's server. Routes
// cannot be removed once registered, so each one looks up the service that
// is running when a request arrives.
func (p *AuthZenPlugin) registerServiceRoutes() {
	patterns := ars.RoutePatterns()
	sort.Strings(patterns)
	for _, pattern := range patterns {
		name := "authzen/ars" + strings.NewReplacer(" ", "-", "{", "", "}", "").Replace(strings.SplitN(pattern, " ", 2)[1])
		p.manager.ExtraRoute(pattern, name, p.serveARS(pattern))
	}
}

func (p *AuthZenPlugin) serveARS(pattern string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
			w.Header().Set("X-Request-ID", reqID)
		}
		p.mu.RLock()
		svc, stopped := p.arsService, p.stopped
		p.mu.RUnlock()
		if stopped || svc == nil {
			jsonError(w, "access request service is not running", http.StatusServiceUnavailable)
			return
		}
		svc.Handler(pattern)(w, r)
	}
}

// startService opens the store and builds the service, when enabled. A
// store that cannot be opened fails Start: an Access Request Endpoint the
// metadata advertises must work.
func (p *AuthZenPlugin) startService(ctx context.Context) error {
	p.mu.RLock()
	cfg := p.cfg
	running := p.arsService != nil
	p.mu.RUnlock()
	sc := &cfg.AccessRequest.Service
	if !sc.Enabled || running {
		return nil
	}
	st, err := p.openStore(ctx, sc)
	if err != nil {
		return fmt.Errorf("access request service: opening store: %w", err)
	}
	auditor, err := newOTelAuditor(ctx)
	if err != nil {
		st.Close()
		return fmt.Errorf("access request service: %w", err)
	}
	var audit ars.Auditor
	if auditor != nil {
		audit = auditor
	} else {
		p.logger.Warn("AuthZEN access request service: no OTLP endpoint is configured (OTEL_EXPORTER_OTLP_ENDPOINT), so audit records are not exported")
	}
	// The service APIs' DPoP proofs are remembered in the store, shared by
	// every replica.
	sc.replay.set(storeReplay{remember: st.RememberJTI})
	cache := newApprovalCache(sc.approvalCacheTTL)
	svc := ars.New(&ars.Deps{
		Store:                  st,
		Callers:                sc.callers,
		Approvers:              sc.approvers,
		Eval:                   p.evalServiceRule,
		Crypto:                 pdpCrypto{ac: &cfg.AccessRequest},
		Rules:                  ars.Rules{Caller: sc.Rules.Caller, Workflow: sc.Rules.Workflow, Approver: sc.Rules.Approver},
		Links:                  ars.Links{Ticket: sc.Links.Ticket, Review: sc.Links.Review},
		BaseURL:                cfg.BaseURL,
		Audience:               cfg.AccessRequest.Audience,
		TaskTTL:                sc.taskTTL,
		MaxApprovalTTL:         sc.maxApprovalTTL,
		IdempotencyRetention:   sc.idempotencyRetention,
		MaxItems:               sc.MaxItems,
		MaxSteps:               sc.MaxSteps,
		Callbacks:              sc.callbacks,
		ApprovalStateTTL:       sc.approvalStateTTL,
		ApprovalStateAudiences: sc.ApprovalStateAudiences,
		OnRevoke:               cache.drop,
		Logger:                 p.logger,
		Audit:                  audit,
		Metrics:                p.metrics,
		Now:                    p.now,
	})
	workerCtx, cancel := context.WithCancel(context.Background())
	p.mu.Lock()
	p.arsService, p.arsStore, p.arsCancel, p.arsAudit, p.approvalCache = svc, st, cancel, auditor, cache
	p.mu.Unlock()
	go svc.RunSweeper(workerCtx)
	go svc.RunPurger(workerCtx)
	go svc.RunCallbacks(workerCtx)
	p.logger.Info("AuthZEN access request service started")
	return nil
}

// stopService stops the workers, flushes the audit records and closes the
// store.
func (p *AuthZenPlugin) stopService() {
	p.mu.Lock()
	cancel, st, auditor := p.arsCancel, p.arsStore, p.arsAudit
	p.arsService, p.arsStore, p.arsCancel, p.arsAudit, p.approvalCache = nil, nil, nil, nil, nil
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if auditor != nil {
		ctx, done := context.WithTimeout(context.Background(), 5*time.Second)
		if err := auditor.Shutdown(ctx); err != nil {
			p.logger.Warn("AuthZEN access request service: flushing audit records: %v", err)
		}
		done()
	}
	if st != nil {
		st.Close()
	}
}

// startMetrics starts OpenTelemetry metrics when an OTLP endpoint is
// configured; without one, measurements are discarded. The backlog gauges
// read the service's store while it runs.
func (p *AuthZenPlugin) startMetrics(ctx context.Context) error {
	p.mu.RLock()
	running := p.otelMetrics != nil
	p.mu.RUnlock()
	if running {
		return nil
	}
	m, err := newOTelMetrics(ctx, func() store.Store {
		p.mu.RLock()
		defer p.mu.RUnlock()
		return p.arsStore
	})
	if err != nil {
		return fmt.Errorf("metrics: %w", err)
	}
	if m == nil {
		return nil
	}
	p.mu.Lock()
	p.otelMetrics = m
	p.mu.Unlock()
	p.metrics.set(m)
	return nil
}

// stopMetrics flushes and stops OpenTelemetry metrics.
func (p *AuthZenPlugin) stopMetrics() {
	p.mu.Lock()
	m := p.otelMetrics
	p.otelMetrics = nil
	p.mu.Unlock()
	if m == nil {
		return
	}
	p.metrics.set(nil)
	ctx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if err := m.Shutdown(ctx); err != nil {
		p.logger.Warn("AuthZEN: flushing metrics: %v", err)
	}
}

// evalServiceRule evaluates one of the service's rules in the policy package.
func (p *AuthZenPlugin) evalServiceRule(ctx context.Context, rule string, input map[string]any) (any, error) {
	snap := p.configSnapshot()
	return p.evalRuleWithTxn(ctx, nil, input, snap.path, rule)
}
