package internal

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

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

	dsn                  string
	taskTTL              time.Duration
	maxApprovalTTL       time.Duration
	idempotencyRetention time.Duration
	callers              *authn.Verifier
	approvers            *authn.Verifier
}

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
