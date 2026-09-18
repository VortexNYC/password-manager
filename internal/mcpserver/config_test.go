package mcpserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/VortexNYC/veil/internal/scrub"
)

func TestConfigIsRemoteNoSecret(t *testing.T) {
	got, err := Config("http://127.0.0.1:4461/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "http://127.0.0.1:4461/mcp" {
		t.Fatalf("url %q", got.URL)
	}
	if got.Headers["Authorization"] != "Bearer ${VEIL_OIDC_TOKEN}" {
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
	t.Setenv("VEIL_HYDRA_ISSUER", "https://id.veil.nyc")
	got, err := Config("https://veil.nyc/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != "https://id.veil.nyc" {
		t.Fatalf("issuer %q", got.Issuer)
	}
}

func TestConfigRequiresURL(t *testing.T) {
	if _, err := Config(""); err == nil {
		t.Fatal("empty url")
	}
}

func TestLaptopConfigNoSecret(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "cursor.jwt")
	sec := filepath.Join(dir, "cursor.hydra")
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZ2VudC1jdXJzb3IifQ.sig"
	if err := os.WriteFile(tok, []byte(jwt+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sec, []byte("hydra-agent-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEIL_OIDC_TOKEN_FILE", tok)
	t.Setenv("VEIL_HYDRA_SECRET_FILE", sec)
	t.Setenv("VEIL_HYDRA_ISSUER", "https://id.veil.nyc")
	t.Setenv("VEIL_AGENT", "cursor")

	got := LaptopConfig("https://veil.nyc")
	if got.Command == "" {
		t.Fatal("command")
	}
	if len(got.Args) != 2 || got.Args[0] != "mcp" || got.Args[1] != "stdio" {
		t.Fatalf("args %v", got.Args)
	}
	if got.Env["VEIL_ORIGIN"] != "https://veil.nyc" {
		t.Fatalf("origin %v", got.Env)
	}
	if got.Env["VEIL_OIDC_TOKEN_FILE"] != tok {
		t.Fatalf("token file %v", got.Env)
	}
	if got.Env["VEIL_HYDRA_SECRET_FILE"] != sec {
		t.Fatalf("secret file %v", got.Env)
	}
	if got.Env["VEIL_AGENT"] != "cursor" {
		t.Fatalf("agent %v", got.Env)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(raw, []byte(jwt)) || scrub.Contains(raw, []byte("hydra-agent-secret")) {
		t.Fatalf("laptop config leaked a secret: %s", raw)
	}
	if scrub.Contains(raw, []byte("${file:")) || scrub.Contains(raw, []byte("${VEIL_")) {
		t.Fatalf("laptop config still interpolates: %s", raw)
	}
}
