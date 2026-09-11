package kratos

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOfficialMFAMethodsEnabled(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	dir := filepath.Dir(file)
	for _, name := range []string{"kratos.yml", "kratos.veil.yml"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		s := string(raw)
		for _, needle := range []string{"totp:", "webauthn:", "lookup_secret:", "issuer: Veil"} {
			if !strings.Contains(s, needle) {
				t.Fatalf("%s missing %s", name, needle)
			}
		}
		if strings.Contains(s, "passwordless: true") {
			t.Fatalf("%s webauthn is first-factor; MFA is password then totp/webauthn", name)
		}
	}
	schema, err := os.ReadFile(filepath.Join(dir, "identity.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{`"totp"`, `"account_name"`, `"webauthn"`} {
		if !strings.Contains(string(schema), needle) {
			t.Fatalf("schema missing %s", needle)
		}
	}
}
