package main

import (
	"fmt"
	"strings"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

// Config is the admin form configuration Silo delivers through Configure.
// Expiry dates, presets and settings live in instance state instead, so
// editing them does not restart the plugin.
type Config struct {
	APIKey  string
	BaseURL string
}

func parseConfig(entries []*pluginv1.ConfigEntry) Config {
	var cfg Config
	for _, entry := range entries {
		if entry == nil || entry.GetValue() == nil {
			continue
		}
		v := entry.GetValue().AsMap()
		if entry.GetKey() == "silo" {
			cfg.APIKey = str(v["api_key"])
			cfg.BaseURL = strings.TrimRight(str(v["base_url"]), "/")
		}
	}
	return cfg
}

// problems lists what stops the plugin from working, for the admin page.
func (c Config) problems() []string {
	if c.APIKey == "" {
		return []string{"No Silo API key: add one with the admin:users scope under the plugin's Silo connection settings. Until then no account can be listed, changed or expired."}
	}
	return nil
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}
