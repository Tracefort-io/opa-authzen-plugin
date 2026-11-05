// Modified by Tracefort (2026) from kanywst/opa-authzen-plugin; see NOTICE.

package main

import (
	"os"

	"github.com/Tracefort-io/opa-authzen-plugin/plugin"
	"github.com/open-policy-agent/opa/cmd"
	"github.com/open-policy-agent/opa/v1/runtime"
)

func main() {
	runtime.RegisterPlugin(plugin.PluginName, plugin.Factory{})

	if err := cmd.RootCommand.Execute(); err != nil {
		os.Exit(1)
	}
}
