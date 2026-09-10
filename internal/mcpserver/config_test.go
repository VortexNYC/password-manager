package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/vortexnyc/password-manager/internal/scrub"
)

func TestConfigIsRemoteNoSecret(t *testing.T) {
	got, err := Config("http://127.0.0.1:4461/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "http://127.0.0.1:4461/mcp" {
		t.Fatalf("url %q", got.URL)
	}
	if got.Headers["Authorization"] != "Bearer ${PWM_OIDC_TOKEN}" {
		t.Fatalf("headers %v", got.Headers)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(raw, []byte("sk_")) {
		t.Fatalf("config leaked a secret: %s", raw)
	}
}

func TestConfigIncludesIssuer(t *testing.T) {
	t.Setenv("PWM_HYDRA_ISSUER", "https://id.vortex.nyc")
	got, err := Config("https://pwm.vortex.nyc/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != "https://id.vortex.nyc" {
		t.Fatalf("issuer %q", got.Issuer)
	}
}

func TestConfigRequiresURL(t *testing.T) {
	if _, err := Config(""); err == nil {
		t.Fatal("empty url")
	}
}
