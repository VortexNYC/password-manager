package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vortexnyc/password-manager/internal/crypto"
	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/scrub"
)

func TestSQLiteRoundTripAndNoPlaintextOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	key, err := crypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenSQLite(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	secret := Secret("sk_live_PLAINTEXT_MUST_NOT_HIT_DISK")
	item := protocol.Item{
		ID:    "stripe",
		OrgID: "org",
		Name:  "stripe",
		Kind:  protocol.ItemAPIKey,
		Owner: protocol.Owner{Kind: protocol.OwnerOrg, ID: "org"},
		URIs:  []string{"https://api.stripe.com"},
	}
	if err := s.PutItem(item, secret); err != nil {
		t.Fatal(err)
	}
	if err := s.PutAgent(protocol.Principal{Kind: protocol.PrincipalAgent, ID: "claude", OrgID: "org"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutGrant(protocol.Grant{
		ID:      "claude:stripe",
		OrgID:   "org",
		AgentID: "claude",
		ItemID:  "stripe",
		Level:   protocol.Level2,
		Actions: []protocol.ActionKind{protocol.ActionFetch},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := s.Item("stripe")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "stripe" {
		t.Fatalf("%+v", got)
	}
	plain, err := s.Secret("stripe")
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != string(secret) {
		t.Fatalf("secret=%q", plain)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) {
		t.Fatal("plaintext secret written to sqlite file")
	}

	// reopen
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenSQLite(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	plain, err = s2.Secret("stripe")
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != string(secret) {
		t.Fatalf("reopen secret=%q", plain)
	}
	g, err := s2.GrantFor("claude", "stripe")
	if err != nil || g == nil || g.Level != protocol.Level2 {
		t.Fatalf("grant=%+v err=%v", g, err)
	}
}

func TestSQLiteWrongKeyCannotReadSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	key, err := crypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenSQLite(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutItem(protocol.Item{ID: "x", OrgID: "o", Name: "x", Kind: protocol.ItemAPIKey, Owner: protocol.Owner{Kind: protocol.OwnerOrg, ID: "o"}}, Secret("secret-value")); err != nil {
		t.Fatal(err)
	}
	s.Close()

	other, err := crypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	s2, err := OpenSQLite(path, other)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := s2.Secret("x"); err == nil {
		t.Fatal("wrong key opened secret")
	}
}

func TestSQLiteAuditHasNoSecret(t *testing.T) {
	dir := t.TempDir()
	key, err := crypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenSQLite(filepath.Join(dir, "vault.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	secret := []byte("sk_audit_secret")
	if err := s.AppendAudit(protocol.AuditEvent{
		Time:     time.Now().UTC(),
		OrgID:    "org",
		AgentID:  "claude",
		ItemID:   "stripe",
		Action:   protocol.ActionFetch,
		Decision: protocol.DecisionAllow,
	}); err != nil {
		t.Fatal(err)
	}
	events, err := s.Audit()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("%d", len(events))
	}
	if scrub.Contains([]byte(events[0].Reason), secret) {
		t.Fatal("secret in audit")
	}
}
