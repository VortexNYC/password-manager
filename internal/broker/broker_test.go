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
