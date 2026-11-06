// Package ars implements the Access Request Service of the AuthZEN Access
// Request and Approval Profile (ARAP), hosted inside the PDP: the Access
// Request Endpoint, the Task Status Endpoint and cancellation, and an
// approver API (a plugin extension, not part of ARAP) for a separately
// deployed approval UI.
//
// Every authorization and routing decision is a Rego rule the operator
// writes; the service carries no deployment-specific logic. State lives in
// a store.Store shared by all replicas.
package ars

import (
	"context"
	"net/http"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
	"github.com/Tracefort-io/opa-authzen-plugin/internal/authn"
	"github.com/open-policy-agent/opa/v1/logging"
)

// clockSkew is the tolerance applied when comparing timestamps produced on
// another host with the local clock (ARAP "Time and Clock Skew").
const clockSkew = 30 * time.Second

// maxBodyBytes bounds request bodies, as the evaluation API does.
const maxBodyBytes = 1 << 20

// Paths served by the service, relative to the PDP base URL.
const (
	RequestsPath = "/access/v1/requests"
	AdminPath    = "/access/v1/admin"
)

// Crypto is the PDP's signing key as the service uses it.
type Crypto interface {
	// VerifyBindingToken checks the signature of a binding_token the PDP
	// issued and returns its claims. Claim validation is the caller's.
	VerifyBindingToken(token string) (map[string]any, error)
	// SignApprovalState signs the claims of an approval.state.
	SignApprovalState(claims map[string]any) (string, error)
}

// Evaluator evaluates a Rego rule in the PDP's policy package.
type Evaluator func(ctx context.Context, rule string, input map[string]any) (any, error)

// Auditor receives an audit record after each state change commits.
type Auditor interface {
	Emit(ctx context.Context, event string, attrs map[string]any)
}

type noAudit struct{}

func (noAudit) Emit(context.Context, string, map[string]any) {}

// Rules names the operator's Rego rules.
type Rules struct {
	Caller   string
	Workflow string
	Approver string
}

// Links are optional URL templates; "{id}" becomes the task id.
type Links struct {
	Ticket string
	Review string
}

// Deps is everything the service needs from the plugin.
type Deps struct {
	Store     store.Store
	Callers   *authn.Verifier
	Approvers *authn.Verifier
	Eval      Evaluator
	Crypto    Crypto
	Rules     Rules
	Links     Links
	// BaseURL is the PDP identifier: the issuer of binding_token and
	// approval.state, the audience of approval.state, and the base of every
	// URL the service returns.
	BaseURL string
	// Audience is the Access Request Service identifier a binding_token
	// must name in `aud`.
	Audience             string
	TaskTTL              time.Duration
	MaxApprovalTTL       time.Duration
	IdempotencyRetention time.Duration
	// MaxItems bounds a bulk submission's items; MaxSteps a workflow's
	// steps. Zero means the default.
	MaxItems int
	MaxSteps int
	// Callbacks enables the Callback Profile; nil rejects `callback`.
	Callbacks *CallbackConfig
	Logger    logging.Logger
	Audit     Auditor
	Now       func() time.Time
}

// Defaults for unset Deps.
const (
	DefaultMaxItems            = 50
	DefaultMaxSteps            = 10
	DefaultCallbackTimeout     = 5 * time.Second
	DefaultCallbackMaxAttempts = 8
)

// Service serves the Access Request Service and approver APIs.
type Service struct {
	d              Deps
	routes         map[string]http.HandlerFunc
	callbackClient *http.Client
}

// RoutePatterns lists the ServeMux patterns the service serves, so routes
// can be registered before a Service exists.
func RoutePatterns() []string {
	var s Service
	out := make([]string, 0, len(s.Routes()))
	for p := range s.Routes() {
		out = append(out, p)
	}
	return out
}

// Handler returns the handler for one of RoutePatterns.
func (s *Service) Handler(pattern string) http.HandlerFunc {
	if h, ok := s.routes[pattern]; ok {
		return h
	}
	return http.NotFound
}

// New returns a Service. Unset Audit, Logger and Now get no-op or real
// defaults, and unset limits the Default values.
func New(deps *Deps) *Service {
	d := *deps
	if d.Audit == nil {
		d.Audit = noAudit{}
	}
	if d.Logger == nil {
		d.Logger = logging.NewNoOpLogger()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.MaxItems <= 0 {
		d.MaxItems = DefaultMaxItems
	}
	if d.MaxSteps <= 0 {
		d.MaxSteps = DefaultMaxSteps
	}
	s := &Service{d: d}
	if d.Callbacks != nil {
		cb := *d.Callbacks
		if cb.Timeout <= 0 {
			cb.Timeout = DefaultCallbackTimeout
		}
		if cb.MaxAttempts <= 0 {
			cb.MaxAttempts = DefaultCallbackMaxAttempts
		}
		s.d.Callbacks = &cb
		s.callbackClient = newCallbackClient(&cb)
	}
	s.routes = s.Routes()
	return s
}

// Routes returns the handlers of the ARAP endpoints and the approver API,
// keyed by ServeMux pattern.
func (s *Service) Routes() map[string]http.HandlerFunc {
	routes := map[string]http.HandlerFunc{
		"POST " + RequestsPath:                    s.handleSubmit,
		"GET " + RequestsPath + "/{id}":           s.handleStatus,
		"POST " + RequestsPath + "/{id}/cancel":   s.handleCancel,
		"DELETE " + RequestsPath + "/{id}/cancel": s.handleCancel,
	}
	for pattern, h := range s.adminRoutes() {
		routes[pattern] = h
	}
	return routes
}

func (s *Service) now() time.Time { return s.d.Now().UTC() }

func (s *Service) statusEndpoint(id string) string {
	return s.d.BaseURL + RequestsPath + "/" + id
}
