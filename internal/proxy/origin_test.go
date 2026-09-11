package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/scrub"
)

func TestOriginInjectsViaUseNotSecret(t *testing.T) {
	const vault = "sk_live_ORIGIN_SECRET"
	var sawItem, sawURL, sawAuth string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("origin HTTP unused; OriginUse is the seam")
	}))
	t.Cleanup(origin.Close)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("child must not hit upstream; origin Use fetches")
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	items := []protocol.Item{{
		ID:   "stripe",
		Name: "stripe",
		Kind: protocol.ItemAPIKey,
		URIs: []string{upstream.URL},
	}}
	s, err := NewOrigin("cursor", dir, items, func(ctx context.Context, item, method, rawURL string, header http.Header, body []byte) (OriginResult, error) {
		sawItem = item
		sawURL = rawURL
		sawAuth = header.Get("Authorization")
		return OriginResult{Decision: protocol.DecisionAllow, Status: 200, Body: `{"ok":true}`}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(s.CAPEM) {
		t.Fatal("ca pem")
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(s.ProxyURL()),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
		Timeout: 8 * time.Second,
	}
	req, err := http.NewRequest(http.MethodGet, upstream.URL+"/v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+DummySecret)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", res.StatusCode, body)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("wrapped Use JSON leaked to child: %s", body)
	}
	if sawItem != "stripe" {
		t.Fatalf("item %q", sawItem)
	}
	if !strings.Contains(sawURL, "/v1") {
		t.Fatalf("url %q", sawURL)
	}
	if dummyValue(sawAuth) {
		t.Fatal("dummy Authorization forwarded to origin Use")
	}
	if scrub.Contains(body, []byte(vault)) {
		t.Fatal("vault secret in child body")
	}
	env := DummyEnv(items)
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "STRIPE="+DummySecret) {
		t.Fatalf("dummy env %q", env)
	}
	if strings.Contains(joined, vault) {
		t.Fatal("vault secret in dummy env")
	}
}

func TestOriginPassThroughNonDummyAuth(t *testing.T) {
	var used bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer session-jwt" {
			t.Fatalf("auth %q", r.Header.Get("Authorization"))
		}
		_, _ = io.WriteString(w, "passthrough")
	}))
	t.Cleanup(upstream.Close)
	dir := t.TempDir()
	items := []protocol.Item{{
		ID:   "cloudflare",
		Name: "cloudflare",
		Kind: protocol.ItemAPIKey,
		URIs: []string{upstream.URL},
	}}
	s, err := NewOrigin("cursor", dir, items, func(ctx context.Context, item, method, rawURL string, header http.Header, body []byte) (OriginResult, error) {
		used = true
		t.Fatal("origin Use on pass-through")
		return OriginResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(s.ProxyURL())},
		Timeout:   8 * time.Second,
	}
	req, err := http.NewRequest(http.MethodGet, upstream.URL+"/client/v4", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer session-jwt")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if string(body) != "passthrough" {
		t.Fatalf("%s", body)
	}
	if used {
		t.Fatal("origin Use")
	}
}

func TestOriginUnknownHostDenied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("unknown host")
	}))
	t.Cleanup(upstream.Close)
	dir := t.TempDir()
	s, err := NewOrigin("cursor", dir, []protocol.Item{{
		ID:   "stripe",
		Name: "stripe",
		Kind: protocol.ItemAPIKey,
		URIs: []string{"https://api.stripe.com"},
	}}, func(ctx context.Context, item, method, rawURL string, header http.Header, body []byte) (OriginResult, error) {
		t.Fatal("use")
		return OriginResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(s.ProxyURL())},
		Timeout:   8 * time.Second,
	}
	res, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", res.StatusCode, body)
	}
	var got protocol.UseResult
	if json.Unmarshal(body, &got) != nil {
		t.Fatalf("%s", body)
	}
	if got.Reason != "host_not_allowed" {
		t.Fatalf("%+v", got)
	}
}

func TestDummyEnvWellKnownCloudflare(t *testing.T) {
	env := DummyEnv([]protocol.Item{{
		Name: "cloudflare",
		Kind: protocol.ItemAPIKey,
		URIs: []string{"https://api.cloudflare.com"},
	}})
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "CLOUDFLARE="+DummySecret) {
		t.Fatalf("%q", env)
	}
	if !strings.Contains(joined, "CLOUDFLARE_API_TOKEN="+DummySecret) {
		t.Fatalf("wrangler token alias missing: %q", env)
	}
}
