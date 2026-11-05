// Modified by Tracefort (2026) from kanywst/opa-authzen-plugin; see NOTICE.

package main

import (
	"testing"

	"github.com/Tracefort-io/opa-authzen-plugin/plugin"
	"github.com/open-policy-agent/opa/v1/plugins"
)

func TestPluginRegistration(t *testing.T) {
	// Verify the factory satisfies the OPA plugin interface.
	var _ plugins.Factory = plugin.Factory{}
}

func TestPluginNameIsAuthzen(t *testing.T) {
	if plugin.PluginName != "authzen" {
		t.Fatalf("expected plugin name 'authzen', got %q", plugin.PluginName)
	}
}
