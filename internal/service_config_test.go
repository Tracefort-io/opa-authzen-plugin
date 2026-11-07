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

const callbackSecretEnv = "TEST_CALLBACK_SECRET"

// senderConstraint sets the caller API's sender_constraint.
func senderConstraint(c map[string]any, sc map[string]any) {
	service(c)["caller_auth"].(map[string]any)["sender_constraint"] = sc
}

func TestPEPAuthConfig(t *testing.T) {
	ok := `{"base_url": "https://pdp.example.com", "pep_auth": {"issuers": [{"issuer": "https://idp.example.com",
		"audience": "https://pdp.example.com", "jwks_uri": "https://idp.example.com/jwks"}],
		"sender_constraint": {"dpop": {"enabled": true}, "mtls": {"enabled": true, "source": "header", "header": "X-Forwarded-Client-Cert", "format": "envoy_xfcc"}}}}`
	cfg, err := Validate(nil, []byte(ok))
	if err != nil || cfg.PEPAuth.verifier == nil {
		t.Fatalf("pep_auth: %v", err)
	}
	for name, conf := range map[string]string{
		"no issuers": `{"pep_auth": {"issuers": []}}`,
		"dpop without base_url": `{"pep_auth": {"issuers": [{"issuer": "https://idp.example.com", "audience": "a",
			"jwks_uri": "https://idp.example.com/jwks"}], "sender_constraint": {"dpop": {"enabled": true}}}}`,
	} {
		if _, err := Validate(nil, []byte(conf)); err == nil || !strings.Contains(err.Error(), "pep_auth") {
			t.Errorf("%s: expected a pep_auth error, got %v", name, err)
		}
	}
}

func callbacksConf(destinations ...any) map[string]any {
	return map[string]any{"destinations": destinations}
}

func TestServiceConfigCallbacks(t *testing.T) {
	t.Setenv(defaultDSNEnv, "postgres://u:p@localhost/db")
	t.Setenv(callbackSecretEnv, strings.Repeat("k", minCallbackSecret))
	cfg, err := Validate(nil, serviceConf(t, func(c map[string]any) {
		s := service(c)
		s["max_items"], s["max_steps"] = 20, 3
		cb := callbacksConf(map[string]any{"host": "PEP.example.com", "hmac_secret_env": callbackSecretEnv, "allow_internal": true})
		cb["timeout"], cb["max_attempts"] = "3s", 4
		s["callbacks"] = cb
	}))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.AccessRequest.Service
	cb := s.callbacks
	if s.MaxItems != 20 || s.MaxSteps != 3 || cb == nil || cb.Timeout != 3*time.Second || cb.MaxAttempts != 4 {
		t.Fatalf("callbacks: %+v %+v", s, cb)
	}
	dest, ok := cb.Destinations["pep.example.com"]
	if !ok || !dest.AllowInternal || string(dest.Secret) != strings.Repeat("k", minCallbackSecret) {
		t.Fatalf("destination: %+v", cb.Destinations)
	}
	// Without the section, callbacks stay off.
	cfg, err = Validate(nil, serviceConf(t, nil))
	if err != nil || cfg.AccessRequest.Service.callbacks != nil {
		t.Fatalf("callbacks without config: %v %+v", err, cfg.AccessRequest.Service.callbacks)
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
		"negative items":   func(c map[string]any) { service(c)["max_items"] = -1 },
		"callbacks without destinations": func(c map[string]any) {
			service(c)["callbacks"] = map[string]any{"destinations": []any{}}
		},
		"callback host with scheme": func(c map[string]any) {
			service(c)["callbacks"] = callbacksConf(map[string]any{"host": "https://pep.example.com", "hmac_secret_env": callbackSecretEnv})
		},
		"callback host listed twice": func(c map[string]any) {
			d := map[string]any{"host": "pep.example.com", "hmac_secret_env": callbackSecretEnv}
			service(c)["callbacks"] = callbacksConf(d, d)
		},
		"callback secret unset": func(c map[string]any) {
			service(c)["callbacks"] = callbacksConf(map[string]any{"host": "pep.example.com", "hmac_secret_env": "UNSET_SECRET_VAR"})
		},
		"callback secret short": func(c map[string]any) {
			service(c)["callbacks"] = callbacksConf(map[string]any{"host": "pep.example.com", "hmac_secret_env": "SHORT_SECRET"})
		},
		"negative state ttl":    func(c map[string]any) { service(c)["approval_state_ttl"] = "-1m" },
		"bad cache ttl":         func(c map[string]any) { service(c)["approval_cache_ttl"] = "often" },
		"bad state audience":    func(c map[string]any) { service(c)["approval_state_audiences"] = []any{"peer-pdp"} },
		"require without proof": func(c map[string]any) { senderConstraint(c, map[string]any{"require": true}) },
		"mtls without source":   func(c map[string]any) { senderConstraint(c, map[string]any{"mtls": map[string]any{"enabled": true}}) },
		"dpop bad max age": func(c map[string]any) {
			senderConstraint(c, map[string]any{"dpop": map[string]any{"enabled": true, "max_age": "long"}})
		},
		"approval issuer file and uri": func(c map[string]any) {
			c["access_request"].(map[string]any)["approval_issuers"] = []any{map[string]any{
				"issuer": "https://ars.example.com", "jwks_file": "/x.json", "jwks_uri": "https://ars.example.com/jwks",
			}}
		},
		"approval issuer without keys": func(c map[string]any) {
			c["access_request"].(map[string]any)["approval_issuers"] = []any{map[string]any{"issuer": "https://ars.example.com"}}
		},
		"callback bad timeout": func(c map[string]any) {
			cb := callbacksConf(map[string]any{"host": "pep.example.com", "hmac_secret_env": callbackSecretEnv})
			cb["timeout"] = "fast"
			service(c)["callbacks"] = cb
		},
	}
	t.Setenv(callbackSecretEnv, strings.Repeat("k", minCallbackSecret))
	t.Setenv("SHORT_SECRET", "too-short")
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
