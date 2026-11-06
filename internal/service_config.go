package internal

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars"
	"github.com/Tracefort-io/opa-authzen-plugin/internal/authn"
)

// Defaults for the hosted Access Request Service.
const (
	defaultDSNEnv               = "AUTHZEN_ARS_DSN"
	defaultSchema               = "authzen_ars"
	defaultMaxConns             = 10
	defaultTaskTTL              = 72 * time.Hour
	defaultMaxApprovalTTL       = 30 * 24 * time.Hour
	defaultIdempotencyRetention = 24 * time.Hour
	requestsPath                = "/access/v1/requests"
)

// ServiceConfig enables the Access Request Service inside the plugin
// (access_request.service). The profile allows the PDP to host it; state
// lives in Postgres so every replica can serve it.
type ServiceConfig struct {
	Enabled      bool           `json:"enabled"`
	Database     DatabaseConfig `json:"database"`
	CallerAuth   AuthConfig     `json:"caller_auth"`
	ApproverAuth AuthConfig     `json:"approver_auth"`
	Rules        ServiceRules   `json:"rules"`
	Links        ServiceLinks   `json:"links"`
	// TaskTTL is the default task.expires_at, as a Go duration.
	TaskTTL string `json:"task_ttl,omitempty"`
	// MaxApprovalTTL caps approved_until, as a Go duration.
	MaxApprovalTTL string `json:"max_approval_ttl,omitempty"`
	// IdempotencyRetention keeps a terminal task and its Idempotency-Key
	// for this long after expires_at, as a Go duration.
	IdempotencyRetention string `json:"idempotency_retention,omitempty"`
	// MaxItems bounds a bulk submission's items.
	MaxItems int `json:"max_items,omitempty"`
	// MaxSteps bounds a workflow's steps.
	MaxSteps int `json:"max_steps,omitempty"`
	// Callbacks enables the Callback Profile; without it a submitted
	// `callback` is rejected.
	Callbacks *CallbacksConfig `json:"callbacks,omitempty"`

	dsn                  string
	taskTTL              time.Duration
	maxApprovalTTL       time.Duration
	idempotencyRetention time.Duration
	callers              *authn.Verifier
	approvers            *authn.Verifier
	callbacks            *ars.CallbackConfig
}

// CallbacksConfig lists the hosts callbacks may be sent to.
type CallbacksConfig struct {
	// Timeout bounds one delivery attempt, as a Go duration.
	Timeout string `json:"timeout,omitempty"`
	// MaxAttempts is how many attempts a notification gets.
	MaxAttempts  int                   `json:"max_attempts,omitempty"`
	Destinations []CallbackDestination `json:"destinations"`
}

// CallbackDestination is one allowed callback host. Its HMAC key is read
// from the environment variable HMACSecretEnv, never from the config file.
type CallbackDestination struct {
	Host          string `json:"host"`
	HMACSecretEnv string `json:"hmac_secret_env"`
	// AllowInternal permits a host that resolves to loopback, private or
	// other internal addresses, such as an in-cluster PEP.
	AllowInternal bool `json:"allow_internal,omitempty"`
}

// minCallbackSecret is the shortest accepted HMAC key: the SHA-256 output
// size, as RFC 2104 recommends.
const minCallbackSecret = 32

// DatabaseConfig locates the Postgres database. The DSN is read from the
// environment variable named by DSNEnv, never from the config file.
type DatabaseConfig struct {
	DSNEnv   string `json:"dsn_env,omitempty"`
	Schema   string `json:"schema,omitempty"`
	MaxConns int32  `json:"max_conns,omitempty"`
}

// AuthConfig lists the token issuers trusted for one API.
type AuthConfig struct {
	Issuers []authn.Issuer `json:"issuers"`
}

// ServiceRules names the Rego rules, in the package at path, that decide
// every authorization question the service asks.
type ServiceRules struct {
	// Caller decides whether a caller may submit, view or cancel.
	Caller string `json:"caller"`
	// Workflow plans the approval steps of a submission.
	Workflow string `json:"workflow"`
	// Approver decides whether an approver may list, view, decide or revoke.
	Approver string `json:"approver"`
}

// ServiceLinks are optional URL templates for task.links.ticket and
// task.links.review; "{id}" is replaced by the task id.
type ServiceLinks struct {
	Ticket string `json:"ticket,omitempty"`
	Review string `json:"review,omitempty"`
}

// load validates the service configuration. It runs from
// AccessRequestConfig.load, after the signing key is loaded.
func (s *ServiceConfig) load(cfg *Config, ac *AccessRequestConfig) error {
	if !s.Enabled {
		return nil
	}
	if cfg.BaseURL == "" {
		return fmt.Errorf("service requires base_url, from which its endpoint URLs are built")
	}
	if ac.signingKey == nil {
		return fmt.Errorf("service requires signing_key_file: submissions are bound to the denial by a PDP-signed binding_token")
	}

	if s.Database.DSNEnv == "" {
		s.Database.DSNEnv = defaultDSNEnv
	}
	if s.dsn = os.Getenv(s.Database.DSNEnv); s.dsn == "" {
		return fmt.Errorf("service database: environment variable %s is empty", s.Database.DSNEnv)
	}
	if s.Database.Schema == "" {
		s.Database.Schema = defaultSchema
	}
	if s.Database.MaxConns == 0 {
		s.Database.MaxConns = defaultMaxConns
	}
	if s.Database.MaxConns < 0 {
		return fmt.Errorf("service database.max_conns must be positive")
	}

	for name, rule := range map[string]string{"caller": s.Rules.Caller, "workflow": s.Rules.Workflow, "approver": s.Rules.Approver} {
		if strings.TrimSpace(rule) == "" {
			return fmt.Errorf("service rules.%s is required", name)
		}
	}

	var err error
	if s.callers, err = authn.NewVerifier(s.CallerAuth.Issuers, nil); err != nil {
		return fmt.Errorf("service caller_auth: %w", err)
	}
	if s.approvers, err = authn.NewVerifier(s.ApproverAuth.Issuers, nil); err != nil {
		return fmt.Errorf("service approver_auth: %w", err)
	}

	for _, d := range []struct {
		name string
		src  string
		dst  *time.Duration
		def  time.Duration
	}{
		{"task_ttl", s.TaskTTL, &s.taskTTL, defaultTaskTTL},
		{"max_approval_ttl", s.MaxApprovalTTL, &s.maxApprovalTTL, defaultMaxApprovalTTL},
		{"idempotency_retention", s.IdempotencyRetention, &s.idempotencyRetention, defaultIdempotencyRetention},
	} {
		*d.dst = d.def
		if strings.TrimSpace(d.src) == "" {
			continue
		}
		v, err := time.ParseDuration(strings.TrimSpace(d.src))
		if err != nil || v <= 0 {
			return fmt.Errorf("service %s %q must be a positive duration", d.name, d.src)
		}
		*d.dst = v
	}

	for name, v := range map[string]int{"max_items": s.MaxItems, "max_steps": s.MaxSteps} {
		if v < 0 {
			return fmt.Errorf("service %s must be positive", name)
		}
	}
	if s.callbacks, err = s.Callbacks.load(); err != nil {
		return fmt.Errorf("service callbacks: %w", err)
	}

	for name, tmpl := range map[string]string{"ticket": s.Links.Ticket, "review": s.Links.Review} {
		if tmpl == "" {
			continue
		}
		u, err := url.Parse(strings.ReplaceAll(tmpl, "{id}", "x"))
		if err != nil || u.Scheme != "https" || u.Host == "" || !strings.Contains(tmpl, "{id}") {
			return fmt.Errorf("service links.%s %q must be an https URL template containing {id}", name, tmpl)
		}
	}

	// The hosted service is the Access Request Endpoint this PDP advertises.
	own := cfg.BaseURL + requestsPath
	switch cfg.AccessRequestEndpoint {
	case "":
		cfg.AccessRequestEndpoint = own
	case own:
	default:
		return fmt.Errorf("access_request_endpoint %q differs from the hosted service's endpoint %q", cfg.AccessRequestEndpoint, own)
	}
	return nil
}

// load validates the callback destinations and reads their keys. A nil
// config leaves callbacks disabled.
func (c *CallbacksConfig) load() (*ars.CallbackConfig, error) {
	if c == nil {
		return nil, nil
	}
	out := &ars.CallbackConfig{
		Timeout:      ars.DefaultCallbackTimeout,
		MaxAttempts:  ars.DefaultCallbackMaxAttempts,
		Destinations: map[string]ars.CallbackDestination{},
	}
	if t := strings.TrimSpace(c.Timeout); t != "" {
		v, err := time.ParseDuration(t)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("timeout %q must be a positive duration", c.Timeout)
		}
		out.Timeout = v
	}
	switch {
	case c.MaxAttempts < 0:
		return nil, fmt.Errorf("max_attempts must be positive")
	case c.MaxAttempts > 0:
		out.MaxAttempts = c.MaxAttempts
	}
	if len(c.Destinations) == 0 {
		return nil, fmt.Errorf("at least one destination is required")
	}
	for i, d := range c.Destinations {
		host := strings.ToLower(strings.TrimSpace(d.Host))
		// A bare host name or IP literal: the scheme is always https and
		// any port on the host is allowed.
		if host == "" || strings.ContainsAny(host, "/:@?#") {
			return nil, fmt.Errorf("destinations[%d].host %q must be a bare host name or IPv4 address", i, d.Host)
		}
		if _, dup := out.Destinations[host]; dup {
			return nil, fmt.Errorf("destinations[%d].host %q is listed twice", i, d.Host)
		}
		if d.HMACSecretEnv == "" {
			return nil, fmt.Errorf("destinations[%d].hmac_secret_env is required", i)
		}
		secret := os.Getenv(d.HMACSecretEnv)
		if len(secret) < minCallbackSecret {
			return nil, fmt.Errorf("destinations[%d]: environment variable %s must hold at least %d bytes", i, d.HMACSecretEnv, minCallbackSecret)
		}
		out.Destinations[host] = ars.CallbackDestination{Secret: []byte(secret), AllowInternal: d.AllowInternal}
	}
	return out, nil
}
