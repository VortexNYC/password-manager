package hydra

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPublicCORSAllowsVaultSPA(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "hydra.yml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, needle := range []string{
		"https://app.veil.nyc",
		"http://127.0.0.1:4470",
		"allow_credentials: false",
	} {
		if !strings.Contains(s, needle) {
			t.Fatalf("hydra public CORS missing %s", needle)
		}
	}
}
