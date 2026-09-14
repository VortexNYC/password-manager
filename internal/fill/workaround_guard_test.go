package fill

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/publicapi"
)

// These tests exist because we shipped green by turning the product off.
// If they fail, we rebuilt a workaround. Do not "fix" them by disabling Touch ID,
// claiming UV, or filling with Confirm == nil.

func TestNilConfirmDoesNotReturnPassword(t *testing.T) {
	a, err := app.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	srv := originAPI(t, a)
	code, raw := originJSON(t, srv, http.MethodPost, "/v1/items", "human", publicapi.CreateItemRequest{
		Name: "github", URI: "https://github.com", Secret: secret, Login: "ada",
	})
	if code != http.StatusOK {
		t.Fatalf("create %d %s", code, raw)
	}
	h := NewOrigin(t.TempDir(), srv.URL, "human")
	if h.Confirm != nil {
		t.Fatal("fixture must leave Confirm nil")
	}
	got := jsonHandle(t, h, map[string]string{"action": "fill", "url": "https://github.com/login"})
	var out struct {
		Entries []jsonFillEntry `json:"entries"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 0 {
		t.Fatalf("nil Confirm filled %+v", out.Entries)
	}
	for _, e := range out.Entries {
		if e.Password != "" {
			t.Fatal("nil Confirm returned a password")
		}
	}
}

func TestChromeProveSourceDoesNotDisableTouchID(t *testing.T) {
	for _, src := range chromeProveSources(t) {
		if bytes.Contains(src, []byte("TouchID:")) {
			t.Fatal("CFT prove wrote fill.json touch_id; Touch ID is the product, not a switch for green")
		}
		if bytes.Contains(src, []byte("PWM_FILL_TOUCHID=0")) {
			t.Fatal("CFT prove disabled Touch ID on the Chrome process")
		}
		if bytes.Contains(src, []byte("envBin()")) {
			t.Fatal("CFT prove used envBin; that forces PWM_FILL_TOUCHID=0. Use envProve")
		}
		if bytes.Contains(src, []byte("fillTab(")) || bytes.Contains(src, []byte("Runtime.evaluate")) {
			t.Fatal("CFT prove filled via evaluate or fillTab; click the chooser")
		}
	}
}

func chromeProveSources(t *testing.T) [][]byte {
	t.Helper()
	hits, err := filepath.Glob("chrome*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) == 0 {
		t.Fatal("no chrome sources")
	}
	var out [][]byte
	for _, p := range hits {
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, src)
	}
	return out
}

func TestChromeProveSourceDoesNotDiscourageUV(t *testing.T) {
	src, err := os.ReadFile("chrome_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(src, []byte("UserVerification=discouraged")) {
		t.Fatal("webauthn.io prove used discouraged UV so the RP would not demand Touch ID")
	}
}

func TestGenerateSourceDoesNotSlugHostIntoInfisicalID(t *testing.T) {
	src, err := os.ReadFile("json.go")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(src, []byte("sanitizeItemName")) || bytes.Contains(src, []byte("generateItemName")) {
		t.Fatal("generate still bends the chooser name to an Infisical id")
	}
	if !strings.Contains(string(src), "name := host") {
		t.Fatal("generate must save the host as the item name")
	}
}

func TestReplicaSourceDoesNotUseDeviceKeyOrPlainSqlite(t *testing.T) {
	src, err := os.ReadFile("replica.go")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(src, []byte("device.key")) || bytes.Contains(src, []byte("OpenOrInit")) || bytes.Contains(src, []byte("OpenReplica")) {
		t.Fatal("replica is a sealed box; device.key sqlite is how agents steal the vault")
	}
}
