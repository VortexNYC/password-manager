package store

import (
	"encoding/json"
	"testing"

	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/scrub"
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
