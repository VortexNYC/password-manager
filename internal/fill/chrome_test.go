package fill

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/VortexNYC/veil/internal/app"
	"github.com/VortexNYC/veil/internal/publicapi"
	"github.com/VortexNYC/veil/internal/scrub"
)

func TestChromeExtensionFill(t *testing.T) {
	if os.Getenv("VEIL_PROVE_CHROME") != "1" {
		t.Skip("VEIL_PROVE_CHROME=1")
	}
	const login = "ada@example.com"
	chrome := chromeForTesting(t)
	if chrome == "" {
		t.Skip("Chrome for Testing not installed (branded Chrome ignores --load-extension)")
	}

	a, err := app.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	origin := originAPI(t, a)

	page := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(repoRoot(t), "apps/fill"))))
	t.Cleanup(page.Close)
	pageURL := strings.TrimRight(page.URL, "/") + "/fixture.html"

	code, raw := originJSON(t, origin, http.MethodPost, "/v1/items", "human", publicapi.CreateItemRequest{
		Name: "stripe", URI: page.URL, Secret: secret, Login: login,
	})
	if code != http.StatusOK {
		t.Fatalf("create %d %s", code, raw)
	}

	userHome := t.TempDir()
	vault := t.TempDir()
	bin := buildPWM(t)
	tok := filepath.Join(vault, "human.jwt")
	if err := os.WriteFile(tok, []byte("human\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InstallOrigin(InstallEnv{Bin: bin, VaultHome: vault, UserHome: userHome, Origin: origin.URL}); err != nil {
		t.Fatal(err)
	}
	if err := WriteHostConfig(vault, HostConfig{
		Origin:    origin.URL,
		Home:      vault,
		TokenFile: tok,
	}); err != nil {
		t.Fatal(err)
	}

	hostBin := HostPath(vault)
	profile := t.TempDir()
	if err := seedProfileHost(profile, hostBin); err != nil {
		t.Fatal(err)
	}
	installCFTHost(t, hostBin)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cdpPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cmd := exec.Command(chrome,
		"--user-data-dir="+profile,
		"--load-extension="+filepath.Join(repoRoot(t), "apps/fill"),
		"--disable-extensions-except="+filepath.Join(repoRoot(t), "apps/fill"),
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-sync",
		"--disable-features=SafeBrowsingEnhancedProtection,Translate,MediaRouter",
		"--window-size=800,600",
		"--remote-debugging-port="+strconv.Itoa(cdpPort),
		"--remote-debugging-address=127.0.0.1",
		"--remote-allow-origins=*",
		"about:blank",
	)
	cmd.Env = envProve()
	// Do not set HOME to a tempdir. CFT then hangs on Page.navigate.
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	waitCDP(t, cdpPort)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	alloc, allocCancel := chromedp.NewRemoteAllocator(ctx, "http://127.0.0.1:"+strconv.Itoa(cdpPort))
	defer allocCancel()
	task, taskCancel := chromedp.NewContext(alloc)
	defer taskCancel()

	var user, pass string
	if err := chromedp.Run(task, chromedp.Navigate(pageURL)); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	if err := chromedp.Run(task, chromedp.WaitVisible("#user")); err != nil {
		t.Fatalf("visible: %v", err)
	}
	if err := chromedp.Run(task, chromedp.Click("#user")); err != nil {
		t.Fatalf("click: %v", err)
	}
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		if err := chromedp.Run(task,
			chromedp.Value("#user", &user),
			chromedp.Value("#pass", &pass),
		); err != nil {
			t.Fatalf("read: %v", err)
		}
		if user == login && pass == secret {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("fields user_len=%d pass_len=%d", len(user), len(pass))
}

func TestChromeExtensionFillCancel(t *testing.T) {
	if os.Getenv("VEIL_PROVE_CHROME") != "1" {
		t.Skip("VEIL_PROVE_CHROME=1")
	}
	const login = "ada@example.com"
	chrome := chromeForTesting(t)
	if chrome == "" {
		t.Skip("Chrome for Testing not installed (branded Chrome ignores --load-extension)")
	}

	a, err := app.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	origin := originAPI(t, a)

	page := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(repoRoot(t), "apps/fill"))))
	t.Cleanup(page.Close)
	pageURL := strings.TrimRight(page.URL, "/") + "/fixture.html"

	code, raw := originJSON(t, origin, http.MethodPost, "/v1/items", "human", publicapi.CreateItemRequest{
		Name: "stripe", URI: page.URL, Secret: secret, Login: login,
	})
	if code != http.StatusOK {
		t.Fatalf("create %d %s", code, raw)
	}

	task := launchCFT(t, chrome, origin)
	if err := chromedp.Run(task, chromedp.Navigate(pageURL)); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	if err := chromedp.Run(task, chromedp.WaitVisible("#user")); err != nil {
		t.Fatalf("visible: %v", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	debugLog := filepath.Join(home, ".veil", "fill-debug.log")
	before, _ := os.ReadFile(debugLog)

	stop := make(chan struct{})
	defer close(stop)
	go dismissTouchID(stop)

	if err := chromedp.Run(task, chromedp.Click("#user")); err != nil {
		t.Fatalf("click: %v", err)
	}

	var user, pass string
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if err := chromedp.Run(task,
			chromedp.Value("#user", &user),
			chromedp.Value("#pass", &pass),
		); err != nil {
			t.Fatalf("read: %v", err)
		}
		if pass != "" || user == login {
			t.Fatalf("cancel filled user_len=%d pass_len=%d", len(user), len(pass))
		}
		delta := debugDelta(before, debugLog)
		if strings.Contains(delta, "confirm ok") || strings.Contains(delta, "confirm reuse") {
			t.Fatalf("cancel still confirmed %q", strings.TrimSpace(delta))
		}
		if strings.Contains(delta, "confirm denied") {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("no confirm denied; user_len=%d pass_len=%d", len(user), len(pass))
}

func debugDelta(before []byte, path string) string {
	after, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if len(after) >= len(before) {
		return string(after[len(before):])
	}
	return string(after)
}

func dismissTouchID(stop <-chan struct{}) {
	// The branded sheet is an NSPanel on the native host, not a
	// coreauthd sheet on Chrome for Testing. Cancel that window.
	// Then Cancel any LocalAuthentication sheet if Authorize was hit.
	// Do not frontmost branded Chrome. Do not synthesize a mouse.
	script := `
tell application "System Events"
	repeat with proc in (every process)
		try
			repeat with w in (windows of proc)
				if name of w is "Veil Access Requested" then
					set frontmost of proc to true
					perform action "AXPress" of button "Cancel" of w
				end if
			end repeat
		end try
		set n to name of proc as text
		if n contains "coreauth" then
			try
				click button "Cancel" of sheet 1 of window 1 of proc
			end try
			try
				click button "Cancel" of window 1 of proc
			end try
		end if
	end repeat
	key code 53
end tell
`
	for {
		select {
		case <-stop:
			return
		default:
		}
		_ = exec.Command("osascript", "-e", script).Run()
		time.Sleep(120 * time.Millisecond)
	}
}

func TestChromeExtensionPasskey(t *testing.T) {
	if os.Getenv("VEIL_PROVE_CHROME") != "1" {
		t.Skip("VEIL_PROVE_CHROME=1")
	}
	chrome := chromeForTesting(t)
	if chrome == "" {
		t.Skip("Chrome for Testing not installed (branded Chrome ignores --load-extension)")
	}

	a, err := app.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	origin := originAPI(t, a)

	page := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(repoRoot(t), "apps/fill"))))
	t.Cleanup(page.Close)
	pageURL := strings.TrimRight(page.URL, "/") + "/passkey-fixture.html"

	userHome := t.TempDir()
	vault := t.TempDir()
	bin := buildPWM(t)
	tok := filepath.Join(vault, "human.jwt")
	if err := os.WriteFile(tok, []byte("human\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InstallOrigin(InstallEnv{Bin: bin, VaultHome: vault, UserHome: userHome, Origin: origin.URL}); err != nil {
		t.Fatal(err)
	}
	if err := WriteHostConfig(vault, HostConfig{
		Origin:    origin.URL,
		Home:      vault,
		TokenFile: tok,
	}); err != nil {
		t.Fatal(err)
	}

	hostBin := HostPath(vault)
	profile := t.TempDir()
	if err := seedProfileHost(profile, hostBin); err != nil {
		t.Fatal(err)
	}
	installCFTHost(t, hostBin)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cdpPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cmd := exec.Command(chrome,
		"--user-data-dir="+profile,
		"--load-extension="+filepath.Join(repoRoot(t), "apps/fill"),
		"--disable-extensions-except="+filepath.Join(repoRoot(t), "apps/fill"),
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-sync",
		"--disable-features=SafeBrowsingEnhancedProtection,Translate,MediaRouter",
		"--window-size=800,600",
		"--remote-debugging-port="+strconv.Itoa(cdpPort),
		"--remote-debugging-address=127.0.0.1",
		"--remote-allow-origins=*",
		"about:blank",
	)
	cmd.Env = envProve()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	waitCDP(t, cdpPort)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	alloc, allocCancel := chromedp.NewRemoteAllocator(ctx, "http://127.0.0.1:"+strconv.Itoa(cdpPort))
	defer allocCancel()
	task, taskCancel := chromedp.NewContext(alloc)
	defer taskCancel()

	if err := chromedp.Run(task, chromedp.Navigate(pageURL)); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	if err := chromedp.Run(task, chromedp.WaitVisible("#register")); err != nil {
		t.Fatalf("visible: %v", err)
	}
	if err := chromedp.Run(task, chromedp.Click("#register")); err != nil {
		t.Fatalf("click: %v", err)
	}
	var status string
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if err := chromedp.Run(task, chromedp.Text("#status", &status)); err != nil {
			t.Fatalf("read: %v", err)
		}
		if strings.HasPrefix(status, "ok ") {
			if err := chromedp.Run(task, chromedp.Click("#login")); err != nil {
				t.Fatalf("login click: %v", err)
			}
			getDeadline := time.Now().Add(20 * time.Second)
			for time.Now().Before(getDeadline) {
				if err := chromedp.Run(task, chromedp.Text("#status", &status)); err != nil {
					t.Fatalf("get read: %v", err)
				}
				if strings.HasPrefix(status, "got ") {
					code, raw := originJSON(t, origin, http.MethodGet, "/v1/items", "human", nil)
					if code != http.StatusOK || !strings.Contains(string(raw), `"kind":"passkey"`) {
						t.Fatalf("origin items %d %s", code, raw)
					}
					return
				}
				if strings.HasPrefix(status, "err ") {
					t.Fatalf("passkey get %s", status)
				}
				time.Sleep(250 * time.Millisecond)
			}
			t.Fatalf("get status %q", status)
		}
		if strings.HasPrefix(status, "err ") {
			t.Fatalf("passkey %s", status)
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("status %q", status)
}

func TestChromeExtensionGenerate(t *testing.T) {
	if os.Getenv("VEIL_PROVE_CHROME") != "1" {
		t.Skip("VEIL_PROVE_CHROME=1")
	}
	chrome := chromeForTesting(t)
	if chrome == "" {
		t.Skip("Chrome for Testing not installed (branded Chrome ignores --load-extension)")
	}

	a, err := app.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	origin := originAPI(t, a)

	page := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(repoRoot(t), "apps/fill"))))
	t.Cleanup(page.Close)
	pageURL := strings.TrimRight(page.URL, "/") + "/generate-fixture.html"

	task := launchCFT(t, chrome, origin)
	if err := chromedp.Run(task, chromedp.Navigate(pageURL)); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	if err := chromedp.Run(task, chromedp.WaitVisible("#pass")); err != nil {
		t.Fatalf("visible: %v", err)
	}
	if err := chromedp.Run(task, chromedp.SendKeys("#user", "ada@example.com")); err != nil {
		t.Fatalf("user: %v", err)
	}
	if err := chromedp.Run(task, chromedp.Click("#pass")); err != nil {
		t.Fatalf("click: %v", err)
	}
	var pass, pass2, user string
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if err := chromedp.Run(task,
			chromedp.Value("#user", &user),
			chromedp.Value("#pass", &pass),
			chromedp.Value("#pass2", &pass2),
		); err != nil {
			t.Fatalf("read: %v", err)
		}
		if len(pass) >= 20 && pass == pass2 {
			code, raw := originJSON(t, origin, http.MethodGet, "/v1/items", "human", nil)
			if code != http.StatusOK {
				t.Fatalf("items %d %s", code, raw)
			}
			if scrub.Contains(raw, []byte(pass)) {
				t.Fatalf("list leaked password")
			}
			var listed publicapi.ItemsResponse
			if err := json.Unmarshal(raw, &listed); err != nil {
				t.Fatal(err)
			}
			if len(listed.Items) != 1 || listed.Items[0].Login != "ada@example.com" {
				t.Fatalf("items %+v", listed.Items)
			}
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("fields user=%q pass_len=%d pass2_len=%d", user, len(pass), len(pass2))
}

func TestChromeExtensionPasskeyWebAuthnIO(t *testing.T) {
	if os.Getenv("VEIL_PROVE_CHROME") != "1" {
		t.Skip("VEIL_PROVE_CHROME=1")
	}
	chrome := chromeForTesting(t)
	if chrome == "" {
		t.Skip("Chrome for Testing not installed (branded Chrome ignores --load-extension)")
	}

	a, err := app.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	origin := originAPI(t, a)
	task := launchCFT(t, chrome, origin)

	user := fmt.Sprintf("veil%d", time.Now().UnixNano())
	page := "https://webauthn.io/?regUserVerification=required&authUserVerification=required"
	if err := chromedp.Run(task, chromedp.Navigate(page)); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	if err := chromedp.Run(task, chromedp.WaitVisible("#input-email")); err != nil {
		t.Fatalf("visible: %v", err)
	}
	if err := chromedp.Run(task, chromedp.SendKeys("#input-email", user)); err != nil {
		t.Fatalf("user: %v", err)
	}
	if err := chromedp.Run(task, chromedp.Click("#register-button")); err != nil {
		t.Fatalf("register: %v", err)
	}
	deadline := time.Now().Add(45 * time.Second)
	registered := false
	for time.Now().Before(deadline) {
		var alert string
		if err := chromedp.Run(task, chromedp.Evaluate(`document.querySelector('[aria-live="polite"]') ? document.querySelector('[aria-live="polite"]').innerText : ""`, &alert)); err != nil {
			t.Fatalf("alert: %v", err)
		}
		if strings.Contains(alert, "Success! Now try to authenticate") {
			registered = true
			break
		}
		if strings.Contains(alert, "Registration failed") || strings.Contains(alert, "Please enter a username") {
			t.Fatalf("register failed: %s", alert)
		}
		time.Sleep(400 * time.Millisecond)
	}
	if !registered {
		t.Fatal("webauthn.io register did not succeed")
	}
	if err := chromedp.Run(task, chromedp.Click("#login-button")); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	deadline = time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		var href string
		if err := chromedp.Run(task, chromedp.Location(&href)); err != nil {
			t.Fatalf("loc: %v", err)
		}
		if strings.Contains(href, "/profile") {
			code, raw := originJSON(t, origin, http.MethodGet, "/v1/items", "human", nil)
			if code != http.StatusOK || !strings.Contains(string(raw), `"kind":"passkey"`) {
				t.Fatalf("origin items %d %s", code, raw)
			}
			return
		}
		var alert string
		_ = chromedp.Run(task, chromedp.Evaluate(`document.querySelector('[aria-live="polite"]') ? document.querySelector('[aria-live="polite"]').innerText : ""`, &alert))
		if strings.Contains(alert, "Authentication failed") {
			t.Fatalf("authenticate failed: %s", alert)
		}
		time.Sleep(400 * time.Millisecond)
	}
	t.Fatal("webauthn.io authenticate did not reach /profile")
}

func launchCFT(t *testing.T, chrome string, origin *httptest.Server) context.Context {
	t.Helper()
	userHome := t.TempDir()
	vault := t.TempDir()
	bin := buildPWM(t)
	tok := filepath.Join(vault, "human.jwt")
	if err := os.WriteFile(tok, []byte("human\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InstallOrigin(InstallEnv{Bin: bin, VaultHome: vault, UserHome: userHome, Origin: origin.URL}); err != nil {
		t.Fatal(err)
	}
	if err := WriteHostConfig(vault, HostConfig{
		Origin:    origin.URL,
		Home:      vault,
		TokenFile: tok,
		Debug:     true,
	}); err != nil {
		t.Fatal(err)
	}
	hostBin := HostPath(vault)
	profile := t.TempDir()
	if err := seedProfileHost(profile, hostBin); err != nil {
		t.Fatal(err)
	}
	installCFTHost(t, hostBin)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cdpPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cmd := exec.Command(chrome,
		"--user-data-dir="+profile,
		"--load-extension="+filepath.Join(repoRoot(t), "apps/fill"),
		"--disable-extensions-except="+filepath.Join(repoRoot(t), "apps/fill"),
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-sync",
		"--disable-features=SafeBrowsingEnhancedProtection,Translate,MediaRouter",
		"--window-size=800,600",
		"--remote-debugging-port="+strconv.Itoa(cdpPort),
		"--remote-debugging-address=127.0.0.1",
		"--remote-allow-origins=*",
		"about:blank",
	)
	cmd.Env = envProve()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	waitCDP(t, cdpPort)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	t.Cleanup(cancel)
	alloc, allocCancel := chromedp.NewRemoteAllocator(ctx, "http://127.0.0.1:"+strconv.Itoa(cdpPort))
	t.Cleanup(allocCancel)
	task, taskCancel := chromedp.NewContext(alloc)
	t.Cleanup(taskCancel)
	return task
}

func chromeForTesting(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("VEIL_CHROME"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		t.Fatalf("VEIL_CHROME=%s missing", p)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	hits, _ := filepath.Glob(filepath.Join(home,
		"Library/Caches/ms-playwright/chromium-*/chrome-mac*/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
	))
	candidates := append([]string{
		"/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
	}, hits...)
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func seedProfileHost(profile, hostBin string) error {
	dir := filepath.Join(profile, "NativeMessagingHosts")
	if err := os.MkdirAll(filepath.Join(profile, "Default"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	prefs := []byte(`{"safebrowsing":{"enabled":false,"enhanced":false},"extensions":{"ui":{"developer_mode":true}}}` + "\n")
	if err := os.WriteFile(filepath.Join(profile, "Default", "Preferences"), prefs, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, JSONHostName+".json"), ManifestJSONChrome(hostBin), 0o644)
}

// installCFTHost writes nyc.veil.fill.json into Chrome for Testing's real
// NativeMessagingHosts. Mac Chromium resolves that dir from the OS user, not
// $HOME. Never branded Chrome. Restored/removed on cleanup.
func installCFTHost(t *testing.T, hostBin string) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, "Library/Application Support/Google/Chrome for Testing/NativeMessagingHosts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, JSONHostName+".json")
	prev, _ := os.ReadFile(path)
	t.Cleanup(func() {
		if len(prev) == 0 {
			_ = os.Remove(path)
			return
		}
		_ = os.WriteFile(path, prev, 0o644)
	})
	if err := os.WriteFile(path, ManifestJSONChrome(hostBin), 0o644); err != nil {
		t.Fatal(err)
	}
}

func waitCDP(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		res, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/json/list", port))
		if err != nil {
			last = err
			time.Sleep(200 * time.Millisecond)
			continue
		}
		raw, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode == 200 && strings.Contains(string(raw), `"type": "page"`) {
			time.Sleep(500 * time.Millisecond)
			return
		}
		last = fmt.Errorf("status %d", res.StatusCode)
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("cdp: %v", last)
}
