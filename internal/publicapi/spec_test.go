package publicapi

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSpecMatchesDocs(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	docs := filepath.Join(filepath.Dir(file), "..", "..", "docs", "openapi", "password-manager.openapi.json")
	want, err := os.ReadFile(docs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Spec, want) {
		t.Fatal("internal/publicapi/spec.json drifted from docs/openapi/password-manager.openapi.json; run pnpm run sdk:generate")
	}
}
