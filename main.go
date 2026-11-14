// Command silo-plugin-guest-accounts is a Silo plugin for time-limited
// accounts: it disables an account when its access ends, and manages which
// libraries each account can see.
package main

import (
	"context"
	_ "embed"
	"os"

	"github.com/hashicorp/go-hclog"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	sdkruntime "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"
)

//go:embed manifest.json
var manifestJSON []byte

// version is stamped at build time with -ldflags "-X main.version=...".
var version = ""

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Name:       "guest-accounts",
		Level:      hclog.Info,
		Output:     os.Stderr,
		JSONFormat: true,
	})

	app := newApp(logger)

	sdkruntime.ServeManifestWithOptions(manifestJSON, version, sdkruntime.CapabilityServers{
		ScheduledTask: &taskServer{app: app},
		HttpRoutes:    &routeServer{app: app},
	}, sdkruntime.WithConfigure(func(ctx context.Context, entries []*pluginv1.ConfigEntry) error {
		app.configure(entries)
		return nil
	}))
}
