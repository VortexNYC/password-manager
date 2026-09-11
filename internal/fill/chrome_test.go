package fill

import (
	"context"
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

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/publicapi"
)

func TestChromeExtensionFill(t *testing.T) {
	if os.Getenv("PWM_PROVE_CHROME") != "1" {
		t.Skip("PWM_PROVE_CHROME=1")
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
	off := false
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
		TouchID:   &off,
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
	cmd.Env = append(envBin(), "PWM_FILL_TOUCHID=0")
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

func chromeForTesting(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("PWM_CHROME"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		t.Fatalf("PWM_CHROME=%s missing", p)
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
// $HOME. Never branded Chrome — kpxc lives there. Restored/removed on cleanup.
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
