package store

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/VortexNYC/veil/internal/protocol"
	"github.com/VortexNYC/veil/internal/scrub"
)

func TestItemJSONDoesNotIncludeSecret(t *testing.T) {
	m := NewMemory()
	secret := Secret("sk_live_hidden")
	item := protocol.Item{
		ID:    "item-1",
		OrgID: "org-1",
		Name:  "stripe",
		Kind:  protocol.ItemAPIKey,
		Owner: protocol.Owner{Kind: protocol.OwnerOrg, ID: "org-1"},
	}
	if err := m.PutItem(item, secret); err != nil {
		t.Fatal(err)
	}
	got, err := m.Item("item-1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(raw, secret) {
		t.Fatalf("item json leaked secret: %s", raw)
	}
	s, err := m.Secret("item-1")
	if err != nil {
		t.Fatal(err)
	}
	if string(s) != string(secret) {
		t.Fatalf("secret=%q", s)
	}
}

func TestMissingGrantIsNilNotError(t *testing.T) {
	m := NewMemory()
	g, err := m.GrantFor("a", "i")
	if err != nil {
		t.Fatal(err)
	}
	if g != nil {
		t.Fatalf("got %+v", g)
	}
}

func TestMemoryRevokeAgentSurvivesReAdd(t *testing.T) {
	m := NewMemory()
	p := protocol.Principal{Kind: protocol.PrincipalAgent, ID: "flue", OrgID: "org"}
	if err := m.PutAgent(p); err != nil {
		t.Fatal(err)
	}
	first := time.Now()
	if err := m.RevokeAgent("flue", first); err != nil {
		t.Fatal(err)
	}
	if err := m.PutAgent(p); err != nil {
		t.Fatal(err)
	}
	got, err := m.Agent("flue")
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(first) {
		t.Fatalf("revoked_at not preserved: %+v", got.RevokedAt)
	}
}

func TestMemoryAppendAudits(t *testing.T) {
	m := NewMemory()
	events := []protocol.AuditEvent{
		{Time: time.Unix(1, 0), OrgID: "o", AgentID: "a1", Action: protocol.ActionFetch, Decision: protocol.DecisionAllow},
		{Time: time.Unix(2, 0), OrgID: "o", AgentID: "a2", Action: protocol.ActionFetch, Decision: protocol.DecisionAllow},
	}
	if err := m.AppendAudits(events); err != nil {
		t.Fatal(err)
	}
	got, err := m.Audit()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(events) {
		t.Fatalf("got %d events", len(got))
	}
	if got[0].AgentID != "a1" || got[1].AgentID != "a2" {
		t.Fatalf("order wrong: %+v", got)
	}
}
