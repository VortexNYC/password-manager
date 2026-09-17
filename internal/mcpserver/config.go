package mcpserver

import (
	"fmt"
	"os"
	"strings"
)

// Remote is the one MCP block every coding agent pastes. URL plus a Bearer
// header template. The token is never in this JSON. The host is not identity.
// Issuer is where the agent mints (Hydra public token+JWKS). Not admin.
type Remote struct {
	URL     string            `json:"url"`
	Issuer  string            `json:"issuer,omitempty"`
	Headers map[string]string `json:"headers"`
}

func Config(publicURL string) (Remote, error) {
	publicURL = strings.TrimSpace(publicURL)
	if publicURL == "" {
		return Remote{}, fmt.Errorf("mcp: url")
	}
	return Remote{
		URL:    publicURL,
		Issuer: strings.TrimSpace(os.Getenv("VEIL_HYDRA_ISSUER")),
		Headers: map[string]string{
			"Authorization": "Bearer ${VEIL_OIDC_TOKEN}",
		},
	}, nil
}

// Laptop is the Cursor (and other GUI) MCP block. Dock-launched apps cannot
// interpolate Bearer or ${file:}. stdio reads VEIL_OIDC_TOKEN_FILE per call.
// mcp laptop writes the env values that are set (paths), never the JWT.
type Laptop struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

func LaptopConfig(origin string) Laptop {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	if origin == "" {
		origin = "https://veil.nyc"
	}
	cmd := "veil"
	if self, err := os.Executable(); err == nil && self != "" {
		cmd = self
	}
	return Laptop{
		Command: cmd,
		Args:    []string{"mcp", "stdio"},
		Env: map[string]string{
			"VEIL_ORIGIN":            origin,
			"VEIL_OIDC_TOKEN_FILE":   strings.TrimSpace(os.Getenv("VEIL_OIDC_TOKEN_FILE")),
			"VEIL_HYDRA_SECRET_FILE": strings.TrimSpace(os.Getenv("VEIL_HYDRA_SECRET_FILE")),
			"VEIL_HYDRA_ISSUER":      strings.TrimSpace(os.Getenv("VEIL_HYDRA_ISSUER")),
			"VEIL_AGENT":             strings.TrimSpace(os.Getenv("VEIL_AGENT")),
		},
	}
}
