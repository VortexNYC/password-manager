package fill

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/veilnyc/password-manager/internal/app"
	"github.com/veilnyc/password-manager/internal/publicapi"
	"github.com/veilnyc/password-manager/internal/scrub"
)

const chromeSavePassword = "typed-chrome-save-pw"

func TestChromeExtensionSave(t *testing.T) {
	if os.Getenv("PWM_PROVE_CHROME") != "1" {
		t.Skip("PWM_PROVE_CHROME=1")
	}
	chrome := chromeForTesting(t)
	if chrome == "" {
		t.Skip("Chrome for Testing not installed (branded Chrome ignores --load-extension)")
	}

	origin, _, pageURL := originSavePage(t)
	task := launchCFT(t, chrome, origin)
	typeLogin(t, task, pageURL)
	clickSave(t, task)

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		code, raw := originJSON(t, origin, http.MethodGet, "/v1/items", "human", nil)
		if code != http.StatusOK {
			t.Fatalf("items %d %s", code, raw)
		}
		if scrub.Contains(raw, []byte(chromeSavePassword)) {
			t.Fatal("list leaked password")
		}
		var listed publicapi.ItemsResponse
		if err := json.Unmarshal(raw, &listed); err != nil {
			t.Fatal(err)
		}
		if len(listed.Items) == 1 && listed.Items[0].Login == "ada@example.com" && !listed.Items[0].HasTOTP {
			if listed.Items[0].Name == "" {
				t.Fatalf("nameless %+v", listed.Items[0])
			}
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("save did not create a login")
}

func TestChromeExtensionSaveCancel(t *testing.T) {
	if os.Getenv("PWM_PROVE_CHROME") != "1" {
		t.Skip("PWM_PROVE_CHROME=1")
	}
	chrome := chromeForTesting(t)
	if chrome == "" {
		t.Skip("Chrome for Testing not installed (branded Chrome ignores --load-extension)")
	}

	origin, _, pageURL := originSavePage(t)
	task := launchCFT(t, chrome, origin)
	typeLogin(t, task, pageURL)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	debugLog := filepath.Join(home, ".password-manager", "fill-debug.log")
	before, _ := os.ReadFile(debugLog)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		deadline := time.Now().Add(25 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-stop:
				return
			default:
			}
			if strings.Contains(debugDelta(before, debugLog), "action=save") {
				dismissTouchID(stop)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	clickSave(t, task)

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		code, raw := originJSON(t, origin, http.MethodGet, "/v1/items", "human", nil)
		if code != http.StatusOK {
			t.Fatalf("items %d %s", code, raw)
		}
		var listed publicapi.ItemsResponse
		if err := json.Unmarshal(raw, &listed); err != nil {
			t.Fatal(err)
		}
		if len(listed.Items) != 0 {
			t.Fatalf("cancel created %+v", listed.Items)
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
	t.Fatal("no confirm denied")
}

func TestChromeExtensionSaveThenEnrollTotp(t *testing.T) {
	if os.Getenv("PWM_PROVE_CHROME") != "1" {
		t.Skip("PWM_PROVE_CHROME=1")
	}
	chrome := chromeForTesting(t)
	if chrome == "" {
		t.Skip("Chrome for Testing not installed (branded Chrome ignores --load-extension)")
	}

	origin, page, pageURL := originSavePage(t)
	totpURL := strings.TrimRight(page.URL, "/") + "/totp-fixture.html"
	task := launchCFT(t, chrome, origin)
	typeLogin(t, task, pageURL)
	clickSave(t, task)

	var uuid string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		code, raw := originJSON(t, origin, http.MethodGet, "/v1/items", "human", nil)
		if code != http.StatusOK {
			t.Fatalf("items %d %s", code, raw)
		}
		if scrub.Contains(raw, []byte(chromeSavePassword)) {
			t.Fatal("list leaked password")
		}
		var listed publicapi.ItemsResponse
		if err := json.Unmarshal(raw, &listed); err != nil {
			t.Fatal(err)
		}
		if len(listed.Items) == 1 && listed.Items[0].Login == "ada@example.com" {
			uuid = listed.Items[0].ID
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if uuid == "" {
		t.Fatal("save did not create a login")
	}

	if err := chromedp.Run(task, chromedp.Navigate(totpURL)); err != nil {
		t.Fatalf("totp: %v", err)
	}
	if err := chromedp.Run(task, chromedp.WaitVisible("#otp")); err != nil {
		t.Fatalf("otp link: %v", err)
	}

	deadline = time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		code, raw := originJSON(t, origin, http.MethodGet, "/v1/items", "human", nil)
		if code != http.StatusOK {
			t.Fatalf("items %d %s", code, raw)
		}
		if scrub.Contains(raw, []byte("JBSWY3DPEHPK3PXP")) {
			t.Fatal("list leaked seed")
		}
		var listed publicapi.ItemsResponse
		if err := json.Unmarshal(raw, &listed); err != nil {
			t.Fatal(err)
		}
		if len(listed.Items) == 1 && listed.Items[0].ID == uuid && listed.Items[0].HasTOTP {
			code, raw = originJSON(t, origin, http.MethodPost, "/v1/fill/totp", "human", publicapi.FillTOTPRequest{UUID: uuid})
			if code != http.StatusOK {
				t.Fatalf("mint %d %s", code, raw)
			}
			if scrub.Contains(raw, []byte("JBSWY3DPEHPK3PXP")) {
				t.Fatal("mint leaked seed")
			}
			var minted publicapi.FillTOTPResponse
			if err := json.Unmarshal(raw, &minted); err != nil || len(minted.TOTP) != 6 {
				t.Fatalf("mint %s", raw)
			}
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("enroll did not attach totp")
}

func originSavePage(t *testing.T) (*httptest.Server, *httptest.Server, string) {
	t.Helper()
	a, err := app.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	origin := originAPI(t, a)
	page := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(repoRoot(t), "apps/fill"))))
	t.Cleanup(page.Close)
	return origin, page, strings.TrimRight(page.URL, "/") + "/fixture.html"
}

func typeLogin(t *testing.T, task context.Context, pageURL string) {
	t.Helper()
	ctx := task
	if err := chromedp.Run(ctx, chromedp.Navigate(pageURL)); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	if err := chromedp.Run(ctx, chromedp.WaitVisible("#pass")); err != nil {
		t.Fatalf("visible: %v", err)
	}
	if err := chromedp.Run(ctx, chromedp.SendKeys("#user", "ada@example.com")); err != nil {
		t.Fatalf("user: %v", err)
	}
	if err := chromedp.Run(ctx, chromedp.SendKeys("#pass", chromeSavePassword)); err != nil {
		t.Fatalf("pass: %v", err)
	}
	var typed string
	if err := chromedp.Run(ctx, chromedp.Value("#pass", &typed)); err != nil || typed != chromeSavePassword {
		t.Fatalf("typed pass_len=%d", len(typed))
	}
	if err := chromedp.Run(ctx, chromedp.Click("#go")); err != nil {
		t.Fatalf("submit: %v", err)
	}
	time.Sleep(400 * time.Millisecond)
}

func clickSave(t *testing.T, parent context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	popup, popCancel := chromedp.NewContext(ctx)
	t.Cleanup(popCancel)
	if err := chromedp.Run(popup, chromedp.Navigate(JSONChromeOrigin()+"popup.html")); err != nil {
		t.Fatalf("popup: %v", err)
	}
	if err := chromedp.Run(popup, chromedp.WaitVisible(`#root`, chromedp.ByQuery)); err != nil {
		t.Fatalf("root: %v", err)
	}
	deadline := time.Now().Add(12 * time.Second)
	var html string
	for time.Now().Before(deadline) {
		if err := chromedp.Run(popup, chromedp.InnerHTML("#root", &html, chromedp.ByQuery)); err != nil {
			t.Fatalf("html: %v", err)
		}
		if strings.Contains(html, "Save this sign-in") {
			if err := chromedp.Run(popup, chromedp.Click(`#root button`, chromedp.ByQuery)); err != nil {
				t.Fatalf("save: %v root=%q", err, html)
			}
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("no save button root=%q", html)
}
