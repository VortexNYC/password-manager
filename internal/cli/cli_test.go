package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/vortexnyc/password-manager/internal/device"
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

func TestCLIApproveOIDCNeedsIssuer(t *testing.T) {
	home := t.TempDir()
	if _, err := run(t, home, "", "init"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "agent", "add", "claude"); err != nil {
		t.Fatal(err)
	}
	secFile := filepath.Join(home, "sec")
	if err := os.WriteFile(secFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "item", "add", "stripe", "--uri", "https://example.com", "--secret-file", secFile); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "grant", "add", "--agent", "claude", "--item", "stripe", "--level", "level1"); err != nil {
		t.Fatal(err)
	}
	tok := filepath.Join(home, "tok")
	if err := os.WriteFile(tok, []byte("not-a-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "approve", "claude:stripe", "--oidc-token-file", tok); err == nil {
		t.Fatal("accepted a token with no hydra issuer")
	}
}

func TestCLIAgentHydraNeedsAgent(t *testing.T) {
	home := t.TempDir()
	if _, err := run(t, home, "", "init"); err != nil {
		t.Fatal(err)
	}
	sec := filepath.Join(home, "hydra-secret")
	if _, err := run(t, home, "", "agent", "hydra", "flue", "--secret-file", sec); err == nil {
		t.Fatal("created a hydra client for a missing agent")
	}
}

func TestCLIAgentHydraNeedsSecretFile(t *testing.T) {
	home := t.TempDir()
	if _, err := run(t, home, "", "init"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "agent", "add", "flue"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "agent", "hydra", "flue"); err == nil {
		t.Fatal("accepted hydra without --secret-file")
	}
}

func TestCLIAgentTokenWritesFileNotStdout(t *testing.T) {
	const hydraSecret = "hydra-agent-secret"
	const jwt = "aaa.bbb.ccc"
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/token" {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "agent-flue" || pass != hydraSecret {
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "client_credentials" {
			t.Fatalf("grant %q", r.Form.Get("grant_type"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": jwt,
			"token_type":   "bearer",
		})
	}))
	t.Cleanup(issuer.Close)
	t.Setenv("PWM_HYDRA_ISSUER", issuer.URL)

	home := t.TempDir()
	secFile := filepath.Join(home, "hydra-secret")
	outFile := filepath.Join(home, "jwt")
	if err := os.WriteFile(secFile, []byte(hydraSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, home, "", "agent", "token", "flue", "--secret-file", secFile, "--out-file", outFile)
	if err != nil {
		t.Fatal(err, out)
	}
	if scrub.Contains([]byte(out), []byte(hydraSecret)) || scrub.Contains([]byte(out), []byte(jwt)) {
		t.Fatalf("token printed secret: %s", out)
	}
	var got struct {
		AgentID  string `json:"agent_id"`
		ClientID string `json:"client_id"`
		OutFile  string `json:"out_file"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err, out)
	}
	if got.AgentID != "flue" || got.ClientID != "agent-flue" || got.OutFile != outFile {
		t.Fatalf("%+v", got)
	}
	raw, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != jwt {
		t.Fatalf("out-file %q", raw)
	}
	st, err := os.Stat(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}

func TestCLIAgentTokenNeedsFiles(t *testing.T) {
	home := t.TempDir()
	if _, err := run(t, home, "", "agent", "token", "flue"); err == nil {
		t.Fatal("accepted token without files")
	}
}

func TestCLIAgentTokenRejectsOpaque(t *testing.T) {
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": "ory_at_opaque",
			"token_type":   "bearer",
		})
	}))
	t.Cleanup(issuer.Close)
	t.Setenv("PWM_HYDRA_ISSUER", issuer.URL)
	home := t.TempDir()
	secFile := filepath.Join(home, "hydra-secret")
	outFile := filepath.Join(home, "jwt")
	if err := os.WriteFile(secFile, []byte("s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "agent", "token", "flue", "--secret-file", secFile, "--out-file", outFile); err == nil {
		t.Fatal("accepted opaque")
	}
	if _, err := os.Stat(outFile); err == nil {
		t.Fatal("wrote out-file on opaque token")
	}
}

func TestCLIFillNeedsVault(t *testing.T) {
	home := t.TempDir()
	if _, err := run(t, home, "", "fill"); err == nil {
		t.Fatal("filled without a vault")
	}
}

func TestCLIServeNeedsVault(t *testing.T) {
	home := t.TempDir()
	if _, err := run(t, home, "", "serve"); err == nil {
		t.Fatal("served without a vault")
	}
}

func TestCLIItemAddTOTPNeverPrintsSeedOrCode(t *testing.T) {
	const seed = "JBSWY3DPEHPK3PXP"
	home := t.TempDir()
	if _, err := run(t, home, "", "init"); err != nil {
		t.Fatal(err)
	}
	var sawTOTP string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawTOTP = r.Header.Get("X-TOTP")
		_, _ = io.WriteString(w, "otp:"+sawTOTP+" seed:"+seed)
	}))
	t.Cleanup(upstream.Close)

	secFile := filepath.Join(home, "sec")
	totpFile := filepath.Join(home, "totp")
	if err := os.WriteFile(secFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(totpFile, []byte(seed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	addOut, err := run(t, home, "", "item", "add", "stripe", "--uri", upstream.URL, "--secret-file", secFile, "--totp-file", totpFile)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains([]byte(addOut), []byte(seed)) || scrub.Contains([]byte(addOut), []byte(secret)) {
		t.Fatalf("item add printed material: %s", addOut)
	}
	if !strings.Contains(addOut, `"has_totp": true`) {
		t.Fatalf("missing has_totp: %s", addOut)
	}
	listOut, err := run(t, home, "", "item", "list")
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains([]byte(listOut), []byte(seed)) {
		t.Fatalf("list printed seed: %s", listOut)
	}

	if _, err := run(t, home, "", "agent", "add", "claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "grant", "add", "--agent", "claude", "--item", "stripe", "--level", "level2"); err != nil {
		t.Fatal(err)
	}
	// use path uses wall clock; assert the CLI result never contains seed or token.
	out, err := run(t, home, "", "use", "--agent", "claude", "--item", "stripe", "--url", upstream.URL+"/v1")
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains([]byte(out), []byte(secret)) || scrub.Contains([]byte(out), []byte(seed)) {
		t.Fatalf("cli printed material: %s", out)
	}
	if sawTOTP == "" || len(sawTOTP) != 6 {
		t.Fatalf("upstream did not see a minted code: %q", sawTOTP)
	}
	if scrub.Contains([]byte(out), []byte(sawTOTP)) {
		t.Fatalf("cli printed minted code: %s", out)
	}
}

func TestCLIRunSetsProxyEnvWithoutVaultSecret(t *testing.T) {
	home := t.TempDir()
	if _, err := run(t, home, "", "init"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "agent", "add", "claude"); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, home, "", "run", "--agent", "claude", "--", "env")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "HTTPS_PROXY=http://claude:") {
		t.Fatalf("missing proxy env: %s", out)
	}
	if scrub.Contains([]byte(out), []byte(secret)) {
		t.Fatal("vault secret in env")
	}
}

func TestCLIRunInjectsGrantedSecretWithoutPrinting(t *testing.T) {
	home := t.TempDir()
	if _, err := run(t, home, "", "init"); err != nil {
		t.Fatal(err)
	}
	secFile := filepath.Join(home, "sec")
	if err := os.WriteFile(secFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "item", "add", "stripe", "--uri", "https://api.stripe.com", "--secret-file", secFile); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "agent", "add", "claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "grant", "add", "--agent", "claude", "--item", "stripe", "--level", "level2"); err != nil {
		t.Fatal(err)
	}
	wantFile := filepath.Join(home, "want")
	if err := os.WriteFile(wantFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, home, "", "run", "--agent", "claude", "--", "sh", "-c", `test "$STRIPE" = "$(cat "`+wantFile+`")" && printf injected`)
	if err != nil {
		t.Fatal(err, out)
	}
	if strings.TrimSpace(out) != "injected" {
		t.Fatalf("child=%q", out)
	}
	if scrub.Contains([]byte(out), []byte(secret)) {
		t.Fatalf("broker printed secret: %s", out)
	}
	list, err := run(t, home, "", "item", "list")
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains([]byte(list), []byte(secret)) {
		t.Fatal("item list leaked")
	}
}

func TestCLIRunSkipsLevel1WithoutPrompt(t *testing.T) {
	home := t.TempDir()
	if _, err := run(t, home, "", "init"); err != nil {
		t.Fatal(err)
	}
	secFile := filepath.Join(home, "sec")
	if err := os.WriteFile(secFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "item", "add", "bank", "--uri", "https://bank.example", "--secret-file", secFile); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "agent", "add", "claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "grant", "add", "--agent", "claude", "--item", "bank", "--level", "level1"); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, home, "", "run", "--agent", "claude", "--", "sh", "-c", `test -z "$BANK" && printf skipped`)
	if err != nil {
		t.Fatal(err, out)
	}
	if strings.TrimSpace(out) != "skipped" {
		t.Fatalf("child=%q", out)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("printed secret: %s", out)
	}
}

func TestCLIUseBodyFileDoesNotPrintSecret(t *testing.T) {
	home := t.TempDir()
	if _, err := run(t, home, "", "init"); err != nil {
		t.Fatal(err)
	}
	var saw string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		saw = string(raw)
		_, _ = io.WriteString(w, "ok")
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
	bodyFile := filepath.Join(home, "body.json")
	if err := os.WriteFile(bodyFile, []byte(`{"email":"a@b.c"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, home, "", "use", "--agent", "claude", "--item", "stripe", "--url", upstream.URL+"/v1", "--method", "POST", "--header", "Content-Type: application/json", "--body-file", bodyFile)
	if err != nil {
		t.Fatal(err, out)
	}
	if scrub.Contains([]byte(out), []byte(secret)) {
		t.Fatalf("cli printed secret: %s", out)
	}
	if saw != `{"email":"a@b.c"}` {
		t.Fatalf("upstream %q", saw)
	}
}

func TestCLIRunInjectFileDoesNotPrintSecret(t *testing.T) {
	home := t.TempDir()
	if _, err := run(t, home, "", "init"); err != nil {
		t.Fatal(err)
	}
	secFile := filepath.Join(home, "sec")
	if err := os.WriteFile(secFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "item", "add", "stripe", "--uri", "https://api.stripe.com", "--secret-file", secFile); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "agent", "add", "claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "grant", "add", "--agent", "claude", "--item", "stripe", "--level", "level2"); err != nil {
		t.Fatal(err)
	}
	tmpl := filepath.Join(home, "tmpl")
	if err := os.WriteFile(tmpl, []byte("token=${STRIPE}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(home, "out.env")
	out, err := run(t, home, "", "run", "--agent", "claude", "--inject", tmpl+":"+dest, "--", "true")
	if err != nil {
		t.Fatal(err, out)
	}
	if scrub.Contains([]byte(out), []byte(secret)) {
		t.Fatalf("broker printed secret: %s", out)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "token="+secret+"\n" {
		t.Fatalf("%q", got)
	}
	bad := filepath.Join(home, "bad")
	if err := os.WriteFile(bad, []byte("${MISSING}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "run", "--agent", "claude", "--inject", bad+":"+filepath.Join(home, "nope"), "--", "true"); err == nil {
		t.Fatal("unknown ref")
	}
}

func TestCLIAuditHasNoSecret(t *testing.T) {
	home := t.TempDir()
	if _, err := run(t, home, "", "init"); err != nil {
		t.Fatal(err)
	}
	secFile := filepath.Join(home, "sec")
	if err := os.WriteFile(secFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "item", "add", "stripe", "--uri", "https://api.stripe.com", "--secret-file", secFile); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "agent", "add", "claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "grant", "add", "--agent", "claude", "--item", "stripe", "--level", "level2"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, home, "", "run", "--agent", "claude", "--", "true"); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, home, "", "audit")
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains([]byte(out), []byte(secret)) {
		t.Fatalf("audit leaked: %s", out)
	}
}

func TestCLIGenOutFileNotJSONSecret(t *testing.T) {
	home := t.TempDir()
	dest := filepath.Join(home, "pw")
	out, err := run(t, home, "", "gen", "--length", "12", "--out-file", dest)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	pw := strings.TrimSpace(string(got))
	if len(pw) != 12 {
		t.Fatalf("%q", got)
	}
	if strings.Contains(out, pw) {
		t.Fatalf("cli printed password: %s", out)
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
			if sub.Flags().Lookup("totp") != nil {
				t.Fatal("do not accept --totp on argv")
			}
			if sub.Flags().Lookup("secret-file") == nil {
				t.Fatal("missing --secret-file")
			}
			if sub.Flags().Lookup("ssh") != nil {
				t.Fatal("do not accept --ssh on argv")
			}
			if sub.Flags().Lookup("ssh-file") == nil {
				t.Fatal("missing --ssh-file")
			}
			if sub.Flags().Lookup("totp-file") == nil {
				t.Fatal("missing --totp-file")
			}
			if sub.Flags().Lookup("refresh") != nil || sub.Flags().Lookup("client-secret") != nil {
				t.Fatal("do not accept oauth secrets on argv")
			}
			if sub.Flags().Lookup("refresh-file") == nil {
				t.Fatal("missing --refresh-file")
			}
			if sub.Flags().Lookup("file") == nil {
				t.Fatal("missing --file")
			}
		}
	}
	for _, c := range cmd.Commands() {
		if c.Name() != "gen" {
			continue
		}
		if c.Flags().Lookup("secret") != nil {
			t.Fatal("do not accept --secret on gen")
		}
		if c.Flags().Lookup("out-file") == nil {
			t.Fatal("missing --out-file")
		}
	}
	for _, c := range cmd.Commands() {
		if c.Name() != "agent" {
			continue
		}
		for _, sub := range c.Commands() {
			if sub.Name() != "token" {
				continue
			}
			if sub.Flags().Lookup("secret") != nil || sub.Flags().Lookup("token") != nil {
				t.Fatal("do not accept --secret or --token on argv")
			}
			if sub.Flags().Lookup("secret-file") == nil || sub.Flags().Lookup("out-file") == nil {
				t.Fatal("missing --secret-file or --out-file")
			}
		}
	}
	for _, c := range cmd.Commands() {
		if c.Name() != "use" {
			continue
		}
		if c.Flags().Lookup("body") != nil {
			t.Fatal("do not accept --body on argv")
		}
		if c.Flags().Lookup("body-file") == nil {
			t.Fatal("missing --body-file")
		}
	}
	for _, c := range cmd.Commands() {
		if c.Name() != "human" {
			continue
		}
		for _, sub := range c.Commands() {
			if sub.Name() != "invite" {
				continue
			}
			if sub.Flags().Lookup("code") != nil {
				t.Fatal("do not accept --code on argv")
			}
			if sub.Flags().Lookup("code-file") == nil {
				t.Fatal("missing --code-file")
			}
		}
	}
}

func TestCLISSHItemListHasNoPrivateKey(t *testing.T) {
	home := t.TempDir()
	if _, err := run(t, home, "", "init"); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(block)
	keyFile := filepath.Join(home, "id_ed25519")
	if err := os.WriteFile(keyFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, home, "", "item", "add", "github", "--ssh-file", keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains([]byte(out), pemBytes) || strings.Contains(out, "PRIVATE KEY") {
		t.Fatalf("cli printed private key: %s", out)
	}
	var item protocol.Item
	if err := json.Unmarshal([]byte(out), &item); err != nil {
		t.Fatal(err, out)
	}
	if item.Kind != protocol.ItemSSH {
		t.Fatalf("kind %q", item.Kind)
	}
	list, err := run(t, home, "", "item", "list")
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains([]byte(list), pemBytes) || strings.Contains(list, "PRIVATE KEY") {
		t.Fatalf("item list leaked pem: %s", list)
	}
}

func TestCLIHumanListHasNoEmail(t *testing.T) {
	t.Setenv("PWM_KRATOS_ADMIN", "http://127.0.0.1:1")
	t.Setenv("PWM_KRATOS_PUBLIC", "http://127.0.0.1:1")
	home := t.TempDir()
	if _, err := run(t, home, "", "init"); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, home, "", "human", "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "self") {
		t.Fatalf("missing planted human: %s", out)
	}
	if strings.Contains(out, "@") {
		t.Fatalf("email in vault list: %s", out)
	}
}

func TestCLIDevicePairOpensSecondHomeAndDoesNotPrintMaster(t *testing.T) {
	src := t.TempDir()
	if _, err := run(t, src, "", "init"); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok:"+r.Header.Get("Authorization"))
	}))
	t.Cleanup(upstream.Close)
	secFile := filepath.Join(src, "sec")
	if err := os.WriteFile(secFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, src, "", "item", "add", "stripe", "--uri", upstream.URL, "--secret-file", secFile); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, src, "", "agent", "add", "claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, src, "", "grant", "add", "--agent", "claude", "--item", "stripe", "--level", "level2"); err != nil {
		t.Fatal(err)
	}

	work := t.TempDir()
	keyFile := filepath.Join(work, "device.key")
	pubFile := filepath.Join(work, "device.pub")
	wrapFile := filepath.Join(work, "wrap.bin")
	newOut, err := run(t, src, "", "device", "new", "--key-file", keyFile)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	master := mustMaster(t, src)
	if scrub.Contains([]byte(newOut), priv) || scrub.Contains([]byte(newOut), master) {
		t.Fatalf("device new leaked: %s", newOut)
	}
	if _, err := run(t, src, "", "device", "pubkey", "--key-file", keyFile, "--out-file", pubFile); err != nil {
		t.Fatal(err)
	}
	offerOut, err := run(t, src, "", "device", "offer", "--pubkey-file", pubFile, "--to-file", wrapFile)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := os.ReadFile(wrapFile)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(wrap, master) || scrub.Contains([]byte(offerOut), master) {
		t.Fatalf("offer leaked master: %s", offerOut)
	}

	dst := t.TempDir()
	for _, name := range []string{"vault.db", "config.json"} {
		raw, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	acceptOut, err := run(t, dst, "", "device", "accept", "--key-file", keyFile, "--from-file", wrapFile)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains([]byte(acceptOut), master) || scrub.Contains([]byte(acceptOut), priv) {
		t.Fatalf("accept leaked: %s", acceptOut)
	}
	if _, err := os.Stat(filepath.Join(dst, "master.key")); err == nil {
		t.Fatal("accept wrote plaintext master.key")
	}
	out, err := run(t, dst, "", "use", "--agent", "claude", "--item", "stripe", "--url", upstream.URL+"/v1")
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains([]byte(out), []byte(secret)) || scrub.Contains([]byte(out), master) {
		t.Fatalf("cli printed secret: %s", out)
	}
}

func TestCLIMCPConfigNoSecret(t *testing.T) {
	home := t.TempDir()
	out, err := run(t, home, "", "mcp", "config")
	if err != nil {
		t.Fatal(err, out)
	}
	if scrub.Contains([]byte(out), []byte(secret)) {
		t.Fatalf("mcp config leaked secret: %s", out)
	}
	var got struct {
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err, out)
	}
	if got.URL != "http://127.0.0.1:4461/mcp" {
		t.Fatalf("url %q", got.URL)
	}
	if got.Headers["Authorization"] != "Bearer ${PWM_OIDC_TOKEN}" {
		t.Fatalf("headers %v", got.Headers)
	}
}

func TestCLIMCPConfigPublicURL(t *testing.T) {
	t.Setenv("PWM_MCP_URL", "https://pwm.vortex.nyc/mcp")
	home := t.TempDir()
	out, err := run(t, home, "", "mcp", "config")
	if err != nil {
		t.Fatal(err, out)
	}
	if !strings.Contains(out, "https://pwm.vortex.nyc/mcp") {
		t.Fatalf("url %s", out)
	}
	if scrub.Contains([]byte(out), []byte(secret)) {
		t.Fatal("mcp config leaked secret")
	}
}

func mustMaster(t *testing.T, dir string) []byte {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, "master.key")); err == nil {
		t.Fatal("plaintext master.key")
	}
	priv, err := os.ReadFile(filepath.Join(dir, "device.key"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := device.Public(priv)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(filepath.Join(dir, "wraps", hex.EncodeToString(pub)))
	if err != nil {
		t.Fatal(err)
	}
	master, err := device.Accept(blob, priv)
	if err != nil {
		t.Fatal(err)
	}
	return master
}
