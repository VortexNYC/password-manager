package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/scrub"
)

const secret = "sk_live_CLI_SECRET"

func run(t *testing.T, home string, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := New("test")
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(append([]string{"--home", home}, args...))
	err := cmd.Execute()
	if err != nil && errb.Len() > 0 {
		return out.String(), err
	}
	return out.String(), err
}

func TestCLILevel2FetchDoesNotPrintSecret(t *testing.T) {
	home := t.TempDir()
	if _, err := run(t, home, "", "init"); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok:"+r.Header.Get("Authorization"))
	}))
	t.Cleanup(upstream.Close)

	secFile := filepath.Join(home, "sec")
	if err := os.WriteFile(secFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "item", "add", "stripe", "--uri", upstream.URL, "--secret-file", secFile); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "agent", "add", "claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "grant", "add", "--agent", "claude", "--item", "stripe", "--level", "level2"); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, home, "", "use", "--agent", "claude", "--item", "stripe", "--url", upstream.URL+"/v1")
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains([]byte(out), []byte(secret)) {
		t.Fatalf("cli printed secret: %s", out)
	}
	var got useDTO
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err, out)
	}
	if got.Decision != protocol.DecisionAllow {
		t.Fatalf("%+v", got)
	}
	if !strings.Contains(got.Body, "ok:") {
		t.Fatalf("body=%q", got.Body)
	}
}

func TestCLILevel1NeedsApprove(t *testing.T) {
	home := t.TempDir()
	if _, err := run(t, home, "", "init"); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	t.Cleanup(upstream.Close)
	secFile := filepath.Join(home, "sec")
	if err := os.WriteFile(secFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "item", "add", "stripe", "--uri", upstream.URL, "--secret-file", secFile); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "agent", "add", "claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "grant", "add", "--agent", "claude", "--item", "stripe", "--level", "level1"); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, home, "", "use", "--agent", "claude", "--item", "stripe", "--url", upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	var got useDTO
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Decision != protocol.DecisionNeedApproval {
		t.Fatalf("%+v", got)
	}
	if _, err := run(t, home, "", "approve", "claude:stripe"); err != nil {
		t.Fatal(err)
	}
	out, err = run(t, home, "", "use", "--agent", "claude", "--item", "stripe", "--url", upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Decision != protocol.DecisionAllow {
		t.Fatalf("%+v %s", got, out)
	}
	if scrub.Contains([]byte(out), []byte(secret)) {
		t.Fatal(out)
	}
}

func TestCLIRejectsSecretOnArgvPattern(t *testing.T) {
	cmd := New("test")
	itemAdd := cmd.Commands()
	_ = itemAdd
	// --secret must not exist. --secret-file is the only path.
	for _, c := range cmd.Commands() {
		if c.Name() != "item" {
			continue
		}
		for _, sub := range c.Commands() {
			if sub.Name() != "add" {
				continue
			}
			if sub.Flags().Lookup("secret") != nil {
				t.Fatal("do not accept --secret on argv")
			}
			if sub.Flags().Lookup("secret-file") == nil {
				t.Fatal("missing --secret-file")
			}
		}
	}
}
