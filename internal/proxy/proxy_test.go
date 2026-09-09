package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/scrub"
)

const secret = "sk_live_PROXY_SECRET"

func startVault(t *testing.T, level protocol.GrantLevel, tlsUpstream bool) (*app.App, *Server, *httptest.Server, *http.Client) {
	t.Helper()
	dir := t.TempDir()
	a, err := app.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Auth", r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, r.Header.Get("Authorization"))
	})
	var upstream *httptest.Server
	if tlsUpstream {
		upstream = httptest.NewTLSServer(handler)
	} else {
		upstream = httptest.NewServer(handler)
	}
	t.Cleanup(upstream.Close)

	if _, err := a.AddItem("stripe", upstream.URL, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddAgent("claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddGrant("claude", "stripe", level); err != nil {
		t.Fatal(err)
	}

	s, err := New(a, "claude", dir)
	if err != nil {
		t.Fatal(err)
	}
	if tlsUpstream {
		s.OutboundTLS = &tls.Config{InsecureSkipVerify: true}
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
			Proxy:             http.ProxyURL(s.ProxyURL()),
			TLSClientConfig:   &tls.Config{RootCAs: pool},
			ForceAttemptHTTP2: false,
		},
		Timeout: 8 * time.Second,
	}
	return a, s, upstream, client
}

func TestHTTPInjectsAndScrubs(t *testing.T) {
	_, s, upstream, client := startVault(t, protocol.Level2, false)
	res, err := client.Get(upstream.URL + "/v1/customers")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", res.StatusCode, body)
	}
	if scrub.Contains(body, []byte(secret)) {
		t.Fatalf("secret in body: %s", body)
	}
	if scrub.Contains([]byte(res.Header.Get("X-Echo-Auth")), []byte(secret)) {
		t.Fatal("secret in header")
	}
	if !bytesContainsRedacted(body) {
		t.Fatalf("expected redaction, body=%s", body)
	}
	events, err := s.App.Store.Audit()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 || events[len(events)-1].Decision != protocol.DecisionAllow {
		t.Fatalf("audit=%+v", events)
	}
}

func TestUnknownHostDenied(t *testing.T) {
	_, _, _, client := startVault(t, protocol.Level2, false)
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be reached")
	}))
	t.Cleanup(evil.Close)
	res, err := client.Get(evil.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d", res.StatusCode)
	}
	var got protocol.UseResult
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Reason != "host_not_allowed" {
		t.Fatalf("%+v", got)
	}
	if err := jsonLeak(got); err != nil {
		t.Fatal(err)
	}
}

func TestBadProxyAuth(t *testing.T) {
	_, s, upstream, _ := startVault(t, protocol.Level2, false)
	u := *s.ProxyURL()
	u.User = nil
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(&u)},
		Timeout:   5 * time.Second,
	}
	res, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status=%d", res.StatusCode)
	}
}

func TestLevel1BlocksUntilApprove(t *testing.T) {
	a, _, upstream, client := startVault(t, protocol.Level1, false)
	res, err := client.Get(upstream.URL + "/v1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", res.StatusCode, body)
	}
	var got protocol.UseResult
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Decision != protocol.DecisionNeedApproval {
		t.Fatalf("%+v", got)
	}
	if scrub.Contains(body, []byte(secret)) {
		t.Fatal(string(body))
	}
	if _, err := a.Approve("claude:stripe", time.Minute); err != nil {
		t.Fatal(err)
	}
	res, err = client.Get(upstream.URL + "/v1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("after approve status=%d body=%s", res.StatusCode, body)
	}
	if scrub.Contains(body, []byte(secret)) {
		t.Fatal(string(body))
	}
}

func TestHTTPSMitmInjects(t *testing.T) {
	_, _, upstream, client := startVault(t, protocol.Level2, true)
	res, err := client.Get(upstream.URL + "/v1/customers")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", res.StatusCode, body)
	}
	if scrub.Contains(body, []byte(secret)) {
		t.Fatalf("secret in https body: %s", body)
	}
}

func TestEnvHasProxyNotVaultSecret(t *testing.T) {
	_, s, _, _ := startVault(t, protocol.Level2, false)
	for _, e := range s.Env() {
		if scrub.Contains([]byte(e), []byte(secret)) {
			t.Fatalf("secret in env %s", e)
		}
	}
}

func bytesContainsRedacted(b []byte) bool {
	return string(b) == scrub.Redacted || len(b) > 0 && !scrub.Contains(b, []byte(secret))
}

func jsonLeak(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if scrub.Contains(b, []byte(secret)) {
		return errSecret(string(b))
	}
	return nil
}

type errSecret string

func (e errSecret) Error() string { return "secret leaked: " + string(e) }
