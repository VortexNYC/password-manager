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
		Issuer: strings.TrimSpace(os.Getenv("PWM_HYDRA_ISSUER")),
		Headers: map[string]string{
			"Authorization": "Bearer ${PWM_OIDC_TOKEN}",
		},
	}, nil
}
