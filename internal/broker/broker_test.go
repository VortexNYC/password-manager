package broker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/vortexnyc/password-manager/internal/material"
	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/scrub"
	"github.com/vortexnyc/password-manager/internal/store"
)

const secret = "sk_live_DO_NOT_LEAK_THIS"

func setup(t *testing.T, level protocol.GrantLevel) (*Broker, protocol.Principal, protocol.Principal, *httptest.Server, string) {
	t.Helper()
	var sawAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.Header().Set("X-Echo-Auth", sawAuth)
		_, _ = io.WriteString(w, `{"ok":true,"echo":"`+strings.TrimPrefix(sawAuth, "Bearer ")+`"}`)
	}))
	t.Cleanup(upstream.Close)

	mem := store.NewMemory()
	agent := protocol.Principal{Kind: protocol.PrincipalAgent, ID: "agent-1", OrgID: "org-1"}
	human := protocol.Principal{Kind: protocol.PrincipalHuman, ID: "human-1", OrgID: "org-1"}
	item := protocol.Item{
		ID:    "item-1",
		OrgID: "org-1",
		Name:  "stripe-live",
		Kind:  protocol.ItemAPIKey,
		Owner: protocol.Owner{Kind: protocol.OwnerOrg, ID: "org-1"},
		URIs:  []string{upstream.URL},
	}
	if err := mem.PutAgent(agent); err != nil {
		t.Fatal(err)
	}
	if err := mem.PutHuman(human); err != nil {
		t.Fatal(err)
	}
	if err := mem.PutItem(item, store.Secret(secret)); err != nil {
		t.Fatal(err)
	}
	if err := mem.PutGrant(protocol.Grant{
		ID:      "grant-1",
		OrgID:   "org-1",
		AgentID: agent.ID,
		ItemID:  item.ID,
		Level:   level,
		Actions: []protocol.ActionKind{protocol.ActionFetch},
	}); err != nil {
		t.Fatal(err)
	}
	b := New(mem)
	b.Now = func() time.Time { return time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC) }
	return b, agent, human, upstream, secret
}

func mustNoLeak(t *testing.T, v any) {
	t.Helper()
	if err := AssertNoSecret(v, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatalf("secret in json: %s", raw)
	}
}

func TestLevel2FetchInjectsAndScrubs(t *testing.T) {
	b, agent, _, upstream, _ := setup(t, protocol.Level2)
	got, err := b.Use(context.Background(), agent, protocol.UseRequest{
		ItemID: "item-1",
		Action: protocol.ActionFetch,
		Fetch:  &protocol.Fetch{URL: upstream.URL + "/v1/customers"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != protocol.DecisionAllow {
		t.Fatalf("decision=%s reason=%s", got.Decision, got.Reason)
	}
	if got.Fetch == nil || got.Fetch.Status != 200 {
		t.Fatalf("fetch=%+v", got.Fetch)
	}
	if scrub.Contains(got.Fetch.Body, []byte(secret)) {
		t.Fatalf("secret in body: %s", got.Fetch.Body)
	}
	if strings.Contains(got.Fetch.Header.Get("X-Echo-Auth"), secret) {
		t.Fatalf("secret in header: %v", got.Fetch.Header)
	}
	mustNoLeak(t, got)
	events, err := b.Store.Audit()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Decision != protocol.DecisionAllow {
		t.Fatalf("audit=%+v", events)
	}
	mustNoLeak(t, events)
}

func TestLevel1BlocksUntilHumanApproves(t *testing.T) {
	b, agent, human, upstream, _ := setup(t, protocol.Level1)
	req := protocol.UseRequest{
		ItemID: "item-1",
		Action: protocol.ActionFetch,
		Fetch:  &protocol.Fetch{URL: upstream.URL + "/v1/customers"},
	}
	got, err := b.Use(context.Background(), agent, req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != protocol.DecisionNeedApproval {
		t.Fatalf("decision=%s", got.Decision)
	}
	if got.Fetch != nil {
		t.Fatal("must not fetch before approval")
	}
	mustNoLeak(t, got)

	if _, err := b.Approve(human, "grant-1", time.Minute); err != nil {
		t.Fatal(err)
	}
	got, err = b.Use(context.Background(), agent, req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != protocol.DecisionAllow {
		t.Fatalf("after approve: %+v", got)
	}
	mustNoLeak(t, got)
}

func TestAgentCannotApprove(t *testing.T) {
	b, agent, _, _, _ := setup(t, protocol.Level1)
	if _, err := b.Approve(agent, "grant-1", time.Minute); err == nil {
		t.Fatal("agent approved")
	}
}

func TestApproveDoesNotConsultSqliteHumans(t *testing.T) {
	b, _, _, _, _ := setup(t, protocol.Level1)
	outsider := protocol.Principal{Kind: protocol.PrincipalHuman, ID: "kratos-id", OrgID: "org-1"}
	if _, err := b.Approve(outsider, "grant-1", time.Minute); err != nil {
		t.Fatal(err)
	}
}

func TestNoGrantDeniedAndNoFetch(t *testing.T) {
	b, _, _, upstream, _ := setup(t, protocol.Level2)
	other := protocol.Principal{Kind: protocol.PrincipalAgent, ID: "agent-2", OrgID: "org-1"}
	if err := b.Store.PutAgent(other); err != nil {
		t.Fatal(err)
	}
	got, err := b.Use(context.Background(), other, protocol.UseRequest{
		ItemID: "item-1",
		Action: protocol.ActionFetch,
		Fetch:  &protocol.Fetch{URL: upstream.URL + "/v1/customers"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != protocol.DecisionDeny {
		t.Fatalf("decision=%s", got.Decision)
	}
	mustNoLeak(t, got)
}

func TestFetchOtherHostDenied(t *testing.T) {
	b, agent, _, _, _ := setup(t, protocol.Level2)
	got, err := b.Use(context.Background(), agent, protocol.UseRequest{
		ItemID: "item-1",
		Action: protocol.ActionFetch,
		Fetch:  &protocol.Fetch{URL: "https://evil.example/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Reason != "host_not_allowed" {
		t.Fatalf("got %+v", got)
	}
}

func TestTOTPMintedAtInjectNeverReturned(t *testing.T) {
	const seed = "JBSWY3DPEHPK3PXP"
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	code, err := totp.GenerateCode(seed, now)
	if err != nil {
		t.Fatal(err)
	}

	var sawAuth, sawTOTP string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawTOTP = r.Header.Get("X-TOTP")
		w.Header().Set("X-Echo-TOTP", sawTOTP)
		_, _ = io.WriteString(w, `{"token":"`+strings.TrimPrefix(sawAuth, "Bearer ")+`","totp":"`+sawTOTP+`","seed":"`+seed+`"}`)
	}))
	t.Cleanup(upstream.Close)

	mem := store.NewMemory()
	agent := protocol.Principal{Kind: protocol.PrincipalAgent, ID: "agent-1", OrgID: "org-1"}
	item := protocol.Item{
		ID:      "item-1",
		OrgID:   "org-1",
		Name:    "stripe-live",
		Kind:    protocol.ItemAPIKey,
		Owner:   protocol.Owner{Kind: protocol.OwnerOrg, ID: "org-1"},
		URIs:    []string{upstream.URL},
		HasTOTP: true,
	}
	blob, err := material.Pack([]byte(secret), []byte(seed))
	if err != nil {
		t.Fatal(err)
	}
	if err := mem.PutAgent(agent); err != nil {
		t.Fatal(err)
	}
	if err := mem.PutItem(item, store.Secret(blob)); err != nil {
		t.Fatal(err)
	}
	if err := mem.PutGrant(protocol.Grant{
		ID:      "grant-1",
		OrgID:   "org-1",
		AgentID: agent.ID,
		ItemID:  item.ID,
		Level:   protocol.Level2,
		Actions: []protocol.ActionKind{protocol.ActionFetch},
	}); err != nil {
		t.Fatal(err)
	}
	b := New(mem)
	b.Now = func() time.Time { return now }

	got, err := b.Use(context.Background(), agent, protocol.UseRequest{
		ItemID: "item-1",
		Action: protocol.ActionFetch,
		Fetch:  &protocol.Fetch{URL: upstream.URL + "/v1/customers"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != protocol.DecisionAllow {
		t.Fatalf("%+v", got)
	}
	if sawAuth != "Bearer "+secret {
		t.Fatalf("auth=%q", sawAuth)
	}
	if sawTOTP != code {
		t.Fatalf("upstream totp=%q want %q", sawTOTP, code)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{secret, seed, code} {
		if scrub.Contains(raw, []byte(leak)) {
			t.Fatalf("leaked %q in %s", leak, raw)
		}
	}
	events, err := b.Store.Audit()
	if err != nil {
		t.Fatal(err)
	}
	mustNoLeak(t, events)
	if scrub.Contains(mustJSON(t, events), []byte(seed)) || scrub.Contains(mustJSON(t, events), []byte(code)) {
		t.Fatal("audit leaked totp material")
	}
}

func TestOAuthRefreshInjectsAccessTokenNeverRefresh(t *testing.T) {
	const refresh = "refresh_DO_NOT_LEAK"
	const access = "access_DO_NOT_LEAK"
	var sawRefresh string
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		sawRefresh = r.Form.Get("refresh_token")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"`+access+`","token_type":"Bearer","expires_in":3600}`)
	}))
	t.Cleanup(tokenSrv.Close)

	var sawAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, sawAuth)
	}))
	t.Cleanup(upstream.Close)

	mem := store.NewMemory()
	agent := protocol.Principal{Kind: protocol.PrincipalAgent, ID: "agent-1", OrgID: "org-1"}
	blob, err := material.PackOAuth([]byte(refresh), []byte(tokenSrv.URL), []byte("client"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	item := protocol.Item{
		ID:    "item-1",
		OrgID: "org-1",
		Name:  "gmail",
		Kind:  protocol.ItemOAuth,
		Owner: protocol.Owner{Kind: protocol.OwnerOrg, ID: "org-1"},
		URIs:  []string{upstream.URL},
	}
	if err := mem.PutAgent(agent); err != nil {
		t.Fatal(err)
	}
	if err := mem.PutItem(item, store.Secret(blob)); err != nil {
		t.Fatal(err)
	}
	if err := mem.PutGrant(protocol.Grant{
		ID:      "grant-1",
		OrgID:   "org-1",
		AgentID: agent.ID,
		ItemID:  item.ID,
		Level:   protocol.Level2,
		Actions: []protocol.ActionKind{protocol.ActionFetch},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := New(mem).Use(context.Background(), agent, protocol.UseRequest{
		ItemID: "item-1",
		Action: protocol.ActionFetch,
		Fetch:  &protocol.Fetch{URL: upstream.URL + "/v1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != protocol.DecisionAllow {
		t.Fatalf("%+v", got)
	}
	if sawRefresh != refresh {
		t.Fatalf("token endpoint saw %q", sawRefresh)
	}
	if sawAuth != "Bearer "+access {
		t.Fatalf("auth=%q", sawAuth)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{refresh, access, "secret"} {
		if scrub.Contains(raw, []byte(leak)) {
			t.Fatalf("leaked %q in %s", leak, raw)
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestChildEnvInjectsLevel2AndScrubsAudit(t *testing.T) {
	b, agent, _, _, sec := setup(t, protocol.Level2)
	pairs, err := b.ChildEnv(context.Background(), agent)
	if err != nil {
		t.Fatal(err)
	}
	want := EnvName("stripe-live") + "=" + sec
	if len(pairs) != 1 || pairs[0] != want {
		t.Fatalf("%q", pairs)
	}
	events, err := b.Store.Audit()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != protocol.ActionEnv || events[0].Decision != protocol.DecisionAllow {
		t.Fatalf("audit=%+v", events)
	}
	mustNoLeak(t, events)
}

func TestChildEnvSkipsLevel1WithoutApproval(t *testing.T) {
	b, agent, _, _, _ := setup(t, protocol.Level1)
	pairs, err := b.ChildEnv(context.Background(), agent)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 0 {
		t.Fatalf("prompted via env: %q", pairs)
	}
	events, err := b.Store.Audit()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Decision != protocol.DecisionNeedApproval {
		t.Fatalf("audit=%+v", events)
	}
	mustNoLeak(t, events)
}

func TestChildEnvSkipsSSH(t *testing.T) {
	mem := store.NewMemory()
	agent := protocol.Principal{Kind: protocol.PrincipalAgent, ID: "agent-1", OrgID: "org-1"}
	item := protocol.Item{
		ID:    "github",
		OrgID: "org-1",
		Name:  "github",
		Kind:  protocol.ItemSSH,
		Owner: protocol.Owner{Kind: protocol.OwnerOrg, ID: "org-1"},
	}
	if err := mem.PutAgent(agent); err != nil {
		t.Fatal(err)
	}
	if err := mem.PutItem(item, store.Secret([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n"))); err != nil {
		t.Fatal(err)
	}
	if err := mem.PutGrant(protocol.Grant{
		ID:      "grant-1",
		OrgID:   "org-1",
		AgentID: agent.ID,
		ItemID:  item.ID,
		Level:   protocol.Level2,
		Actions: []protocol.ActionKind{protocol.ActionFetch},
	}); err != nil {
		t.Fatal(err)
	}
	pairs, err := New(mem).ChildEnv(context.Background(), agent)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 0 {
		t.Fatalf("ssh in env: %q", pairs)
	}
}

func TestChildEnvSkipsFileAndArchived(t *testing.T) {
	mem := store.NewMemory()
	agent := protocol.Principal{Kind: protocol.PrincipalAgent, ID: "agent-1", OrgID: "org-1"}
	if err := mem.PutAgent(agent); err != nil {
		t.Fatal(err)
	}
	file := protocol.Item{
		ID:      "note",
		OrgID:   "org-1",
		Name:    "note",
		Kind:    protocol.ItemFile,
		Owner:   protocol.Owner{Kind: protocol.OwnerOrg, ID: "org-1"},
		HasFile: true,
	}
	archived := protocol.Item{
		ID:       "old",
		OrgID:    "org-1",
		Name:     "old",
		Kind:     protocol.ItemAPIKey,
		Owner:    protocol.Owner{Kind: protocol.OwnerOrg, ID: "org-1"},
		Archived: true,
	}
	if err := mem.PutItem(file, store.Secret([]byte("file-secret"))); err != nil {
		t.Fatal(err)
	}
	if err := mem.PutItem(archived, store.Secret([]byte(secret))); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"note", "old"} {
		if err := mem.PutGrant(protocol.Grant{
			ID:      "g-" + id,
			OrgID:   "org-1",
			AgentID: agent.ID,
			ItemID:  id,
			Level:   protocol.Level2,
			Actions: []protocol.ActionKind{protocol.ActionFetch},
		}); err != nil {
			t.Fatal(err)
		}
	}
	pairs, err := New(mem).ChildEnv(context.Background(), agent)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 0 {
		t.Fatalf("env=%q", pairs)
	}
}

func TestChildEnvMintsTOTPNotSeed(t *testing.T) {
	const seed = "JBSWY3DPEHPK3PXP"
	mem := store.NewMemory()
	agent := protocol.Principal{Kind: protocol.PrincipalAgent, ID: "agent-1", OrgID: "org-1"}
	blob, err := material.Pack([]byte(secret), []byte(seed))
	if err != nil {
		t.Fatal(err)
	}
	item := protocol.Item{
		ID:      "stripe",
		OrgID:   "org-1",
		Name:    "stripe",
		Kind:    protocol.ItemAPIKey,
		Owner:   protocol.Owner{Kind: protocol.OwnerOrg, ID: "org-1"},
		HasTOTP: true,
	}
	if err := mem.PutAgent(agent); err != nil {
		t.Fatal(err)
	}
	if err := mem.PutItem(item, store.Secret(blob)); err != nil {
		t.Fatal(err)
	}
	if err := mem.PutGrant(protocol.Grant{
		ID:      "grant-1",
		OrgID:   "org-1",
		AgentID: agent.ID,
		ItemID:  item.ID,
		Level:   protocol.Level2,
		Actions: []protocol.ActionKind{protocol.ActionFetch},
	}); err != nil {
		t.Fatal(err)
	}
	b := New(mem)
	b.Now = func() time.Time { return time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC) }
	pairs, err := b.ChildEnv(context.Background(), agent)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(pairs, "\n")
	if !strings.HasPrefix(joined, "STRIPE="+secret+"\nSTRIPE_TOTP=") {
		t.Fatalf("%q", pairs)
	}
	code := strings.TrimPrefix(pairs[1], "STRIPE_TOTP=")
	if len(code) != 6 {
		t.Fatalf("totp %q", code)
	}
	if strings.Contains(joined, seed) {
		t.Fatal("seed in env")
	}
	events, err := b.Store.Audit()
	if err != nil {
		t.Fatal(err)
	}
	mustNoLeak(t, events)
	if scrub.Contains(mustJSON(t, events), []byte(seed)) {
		t.Fatal("seed in audit")
	}
}
