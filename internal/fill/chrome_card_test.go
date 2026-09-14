package fill

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/material"
	"github.com/vortexnyc/password-manager/internal/publicapi"
	"github.com/vortexnyc/password-manager/internal/scrub"
)

func TestChromeExtensionCardClickDoesNotFill(t *testing.T) {
	if os.Getenv("PWM_PROVE_CHROME") != "1" {
		t.Skip("PWM_PROVE_CHROME=1")
	}
	const pan = "4111111111111111"
	chrome := chromeForTesting(t)
	if chrome == "" {
		t.Skip("Chrome for Testing not installed (branded Chrome ignores --load-extension)")
	}

	origin, pageURL := originCheckout(t, pan, "123")
	task := launchCFT(t, chrome, origin)
	if err := chromedp.Run(task, chromedp.Navigate(pageURL)); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	if err := chromedp.Run(task, chromedp.WaitVisible("#number")); err != nil {
		t.Fatalf("visible: %v", err)
	}
	if err := chromedp.Run(task, chromedp.Click("#number")); err != nil {
		t.Fatalf("click: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		number, cvv := readCardFields(t, task)
		if number != "" || cvv != "" {
			t.Fatal("card execute without uuid")
		}
		if pageFlag(t, task, "paid") || pageFlag(t, task, "submitted") {
			t.Fatal("clicked pay")
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func TestChromeExtensionCardFill(t *testing.T) {
	if os.Getenv("PWM_PROVE_CHROME") != "1" {
		t.Skip("PWM_PROVE_CHROME=1")
	}
	const pan = "4111111111111111"
	const cvv = "123"
	chrome := chromeForTesting(t)
	if chrome == "" {
		t.Skip("Chrome for Testing not installed (branded Chrome ignores --load-extension)")
	}

	origin, pageURL := originCheckout(t, pan, cvv)
	task := launchCFT(t, chrome, origin)
	if err := chromedp.Run(task, chromedp.Navigate(pageURL)); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	if err := chromedp.Run(task, chromedp.WaitVisible("#number")); err != nil {
		t.Fatalf("visible: %v", err)
	}
	clickChooser(t, task)

	var number, month, year, csc, name string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if pageFlag(t, task, "paid") || pageFlag(t, task, "submitted") {
			t.Fatal("clicked pay")
		}
		number, csc = readCardFields(t, task)
		if err := chromedp.Run(task,
			chromedp.Value("#exp-month", &month),
			chromedp.Value("#exp-year", &year),
			chromedp.Value("#cc-name", &name),
		); err != nil {
			t.Fatalf("read: %v", err)
		}
		if number == pan && csc == cvv && month == "12" && year == "2030" && name == "Ada" {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("card fields number_len=%d cvv_len=%d month=%q year=%q name_len=%d", len(number), len(csc), month, year, len(name))
}

func TestChromeExtensionIdentityFill(t *testing.T) {
	if os.Getenv("PWM_PROVE_CHROME") != "1" {
		t.Skip("PWM_PROVE_CHROME=1")
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
	blob, err := material.PackIdentity("Ada", "Lovelace", "1 Street", "", "", "", "", "+44")
	if err != nil {
		t.Fatal(err)
	}
	code, raw := originJSON(t, origin, http.MethodPost, "/v1/items", "human", publicapi.CreateItemRequest{
		Name: "home", Kind: "identity", Secret: string(blob),
	})
	if code != http.StatusOK {
		t.Fatalf("create %d %s", code, raw)
	}

	page := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(repoRoot(t), "apps/fill"))))
	t.Cleanup(page.Close)
	pageURL := strings.TrimRight(page.URL, "/") + "/identity-fixture.html"

	task := launchCFT(t, chrome, origin)
	if err := chromedp.Run(task, chromedp.Navigate(pageURL)); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	if err := chromedp.Run(task, chromedp.WaitVisible("#given")); err != nil {
		t.Fatalf("visible: %v", err)
	}
	clickChooser(t, task)

	var given, family, addr, phone string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if pageFlag(t, task, "continued") || pageFlag(t, task, "submitted") {
			t.Fatal("clicked continue")
		}
		if err := chromedp.Run(task,
			chromedp.Value("#given", &given),
			chromedp.Value("#family", &family),
			chromedp.Value("#address-line", &addr),
			chromedp.Value("#phone", &phone),
		); err != nil {
			t.Fatalf("read: %v", err)
		}
		if given == "Ada" && family == "Lovelace" && addr == "1 Street" && phone == "+44" {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("identity given_len=%d family_len=%d addr_len=%d phone_len=%d", len(given), len(family), len(addr), len(phone))
}

func originCheckout(t *testing.T, pan, cvv string) (*httptest.Server, string) {
	t.Helper()
	a, err := app.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	origin := originAPI(t, a)
	blob, err := material.PackCard(pan, "12", "2030", cvv, "Ada")
	if err != nil {
		t.Fatal(err)
	}
	code, raw := originJSON(t, origin, http.MethodPost, "/v1/items", "human", publicapi.CreateItemRequest{
		Name: "amex", Kind: "card", Secret: string(blob),
	})
	if code != http.StatusOK {
		t.Fatalf("create %d %s", code, raw)
	}
	if scrub.Contains(raw, []byte(pan)) || scrub.Contains(raw, []byte(cvv)) {
		t.Fatal("create echoed card secret")
	}
	page := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(repoRoot(t), "apps/fill"))))
	t.Cleanup(page.Close)
	return origin, strings.TrimRight(page.URL, "/") + "/checkout-fixture.html"
}

func clickChooser(t *testing.T, parent context.Context) {
	t.Helper()
	popup, cancel := chromedp.NewContext(parent)
	t.Cleanup(cancel)
	if err := chromedp.Run(popup, chromedp.Navigate(JSONChromeOrigin()+"popup.html")); err != nil {
		t.Fatalf("popup: %v", err)
	}
	if err := chromedp.Run(popup, chromedp.WaitVisible(`#root button`, chromedp.ByQuery)); err != nil {
		var html string
		_ = chromedp.Run(popup, chromedp.InnerHTML("#root", &html, chromedp.ByQuery))
		t.Fatalf("chooser: %v root=%q", err, html)
	}
	if err := chromedp.Run(popup, chromedp.Click(`#root button`, chromedp.ByQuery)); err != nil {
		t.Fatalf("choose: %v", err)
	}
}

func readCardFields(t *testing.T, task context.Context) (number, cvv string) {
	t.Helper()
	if err := chromedp.Run(task,
		chromedp.Value("#number", &number),
		chromedp.Value("#cvv", &cvv),
	); err != nil {
		t.Fatalf("read: %v", err)
	}
	return number, cvv
}

func pageFlag(t *testing.T, task context.Context, key string) bool {
	t.Helper()
	switch key {
	case "paid", "submitted", "continued":
	default:
		t.Fatalf("flag %s", key)
	}
	var v string
	expr := `document.documentElement.getAttribute("data-` + key + `") || ""`
	if err := chromedp.Run(task, chromedp.Evaluate(expr, &v)); err != nil {
		t.Fatalf("flag: %v", err)
	}
	return v == "1"
}
