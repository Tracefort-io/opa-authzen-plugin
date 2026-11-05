package internal

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// serviceConf returns a valid enabled-service config, applying edit to its
// decoded form so each case can break one thing.
func serviceConf(t *testing.T, edit func(map[string]any)) []byte {
	t.Helper()
	priv, _, _ := testKey(t, t.TempDir(), "pdp-1")
	conf := map[string]any{
		"base_url": pdpID,
		"access_request": map[string]any{
			"signing_key_file": priv,
			"audience":         pdpID,
			"service": map[string]any{
				"enabled":       true,
				"caller_auth":   map[string]any{"issuers": []any{map[string]any{"issuer": "https://idp.example.com", "audience": pdpID, "jwks_uri": "https://idp.example.com/jwks"}}},
				"approver_auth": map[string]any{"issuers": []any{map[string]any{"issuer": "https://idp.example.com", "audience": "approver-api", "jwks_uri": "https://idp.example.com/jwks"}}},
				"rules":         map[string]any{"caller": "ars_caller", "workflow": "ars_workflow", "approver": "ars_approver"},
			},
		},
	}
	if edit != nil {
		edit(conf)
	}
	b, err := json.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func service(c map[string]any) map[string]any {
	return c["access_request"].(map[string]any)["service"].(map[string]any)
}

func TestServiceConfigDefaults(t *testing.T) {
	t.Setenv(defaultDSNEnv, "postgres://u:p@localhost/db")
	cfg, err := Validate(nil, serviceConf(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.AccessRequest.Service
	if s.dsn != "postgres://u:p@localhost/db" || s.Database.Schema != defaultSchema || s.Database.MaxConns != defaultMaxConns {
		t.Fatalf("database defaults: %+v dsn=%q", s.Database, s.dsn)
	}
	if s.taskTTL != defaultTaskTTL || s.maxApprovalTTL != defaultMaxApprovalTTL || s.idempotencyRetention != defaultIdempotencyRetention {
		t.Fatalf("duration defaults: %v %v %v", s.taskTTL, s.maxApprovalTTL, s.idempotencyRetention)
	}
	if s.callers == nil || s.approvers == nil {
		t.Fatal("verifiers not built")
	}
	if cfg.AccessRequestEndpoint != pdpID+requestsPath {
		t.Fatalf("access_request_endpoint not derived: %q", cfg.AccessRequestEndpoint)
	}
}

func TestServiceConfigOverrides(t *testing.T) {
	t.Setenv("MY_DSN", "postgres://x")
	cfg, err := Validate(nil, serviceConf(t, func(c map[string]any) {
		s := service(c)
		s["database"] = map[string]any{"dsn_env": "MY_DSN", "schema": "ars", "max_conns": 3}
		s["task_ttl"] = "2h"
		s["max_approval_ttl"] = "24h"
		s["links"] = map[string]any{"ticket": "https://ui.example.com/requests/{id}"}
		c["access_request_endpoint"] = pdpID + requestsPath
	}))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.AccessRequest.Service
	if s.dsn != "postgres://x" || s.Database.Schema != "ars" || s.Database.MaxConns != 3 || s.taskTTL != 2*time.Hour || s.maxApprovalTTL != 24*time.Hour {
		t.Fatalf("overrides: %+v", s)
	}
}

func TestServiceConfigRejects(t *testing.T) {
	t.Setenv(defaultDSNEnv, "postgres://u:p@localhost/db")
	cases := map[string]func(map[string]any){
		"no base_url": func(c map[string]any) { delete(c, "base_url") },
		"no signing key": func(c map[string]any) {
			ar := c["access_request"].(map[string]any)
			delete(ar, "signing_key_file")
			delete(ar, "audience")
		},
		"empty dsn env":    func(c map[string]any) { service(c)["database"] = map[string]any{"dsn_env": "UNSET_DSN_VAR"} },
		"no caller rule":   func(c map[string]any) { service(c)["rules"].(map[string]any)["caller"] = "" },
		"no workflow rule": func(c map[string]any) { delete(service(c)["rules"].(map[string]any), "workflow") },
		"no issuers":       func(c map[string]any) { service(c)["approver_auth"] = map[string]any{"issuers": []any{}} },
		"bad ttl":          func(c map[string]any) { service(c)["task_ttl"] = "soon" },
		"zero ttl":         func(c map[string]any) { service(c)["max_approval_ttl"] = "0s" },
		"link no id": func(c map[string]any) {
			service(c)["links"] = map[string]any{"review": "https://ui.example.com/review"}
		},
		"link not https":   func(c map[string]any) { service(c)["links"] = map[string]any{"ticket": "http://ui.example.com/{id}"} },
		"foreign endpoint": func(c map[string]any) { c["access_request_endpoint"] = "https://elsewhere.example.com/requests" },
		"negative conns":   func(c map[string]any) { service(c)["database"] = map[string]any{"max_conns": -1} },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Validate(nil, serviceConf(t, edit))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), "access_request") {
				t.Fatalf("error should name the section: %v", err)
			}
		})
	}
}

func TestServiceDisabledIgnoresServiceSettings(t *testing.T) {
	cfg, err := Validate(nil, []byte(`{"access_request": {"service": {"enabled": false, "rules": {}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AccessRequestEndpoint != "" {
		t.Fatalf("disabled service must not advertise an endpoint: %q", cfg.AccessRequestEndpoint)
	}
}
