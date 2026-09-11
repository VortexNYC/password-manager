package store

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vortexnyc/password-manager/internal/crypto"
	"github.com/vortexnyc/password-manager/internal/material"
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
	var sealed []byte
	if err := s2.db.QueryRow(`SELECT secret FROM items WHERE id=?`, "stripe").Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.Open(key, sealed); err == nil {
		t.Fatal("item still sealed with master; owner DEK unused")
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

func TestSQLiteTOTPSeedNotOnDiskAndHasTOTPPersists(t *testing.T) {
	const seed = "JBSWY3DPEHPK3PXP"
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

	blob, err := material.Pack([]byte("sk_live_token"), []byte(seed))
	if err != nil {
		t.Fatal(err)
	}
	item := protocol.Item{
		ID:      "gmail",
		OrgID:   "org",
		Name:    "gmail",
		Kind:    protocol.ItemAPIKey,
		Owner:   protocol.Owner{Kind: protocol.OwnerOrg, ID: "org"},
		HasTOTP: true,
	}
	if err := s.PutItem(item, Secret(blob)); err != nil {
		t.Fatal(err)
	}
	got, err := s.Item("gmail")
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasTOTP {
		t.Fatal("has_totp dropped")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(seed)) || bytes.Contains(raw, []byte("sk_live_token")) {
		t.Fatal("totp seed or token written in plaintext")
	}
}

func TestSQLiteOwnerKeysDifferAndGrantHasNoDEK(t *testing.T) {
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

	org := protocol.Owner{Kind: protocol.OwnerOrg, ID: "org"}
	user := protocol.Owner{Kind: protocol.OwnerUser, ID: "self"}
	if err := s.PutItem(protocol.Item{ID: "stripe", OrgID: "org", Name: "stripe", Kind: protocol.ItemAPIKey, Owner: org}, Secret("sk_org")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutItem(protocol.Item{ID: "gmail", OrgID: "org", Name: "gmail", Kind: protocol.ItemAPIKey, Owner: user}, Secret("sk_user")); err != nil {
		t.Fatal(err)
	}
	dekOrg, err := s.ownerDEK(org)
	if err != nil {
		t.Fatal(err)
	}
	dekUser, err := s.ownerDEK(user)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dekOrg, dekUser) {
		t.Fatal("owners share a DEK")
	}
	var userBlob []byte
	if err := s.db.QueryRow(`SELECT secret FROM items WHERE id=?`, "gmail").Scan(&userBlob); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.Open(dekOrg, userBlob); err == nil {
		t.Fatal("org DEK opened another owner's item")
	}
	got, err := s.Secret("gmail")
	if err != nil || string(got) != "sk_user" {
		t.Fatalf("gmail=%q err=%v", got, err)
	}

	if err := s.PutGrant(protocol.Grant{
		ID: "claude:stripe", OrgID: "org", AgentID: "claude", ItemID: "stripe",
		Level: protocol.Level2, Actions: []protocol.ActionKind{protocol.ActionFetch},
	}); err != nil {
		t.Fatal(err)
	}
	grants, err := s.ListGrants()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(grants)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(raw, dekOrg) || scrub.Contains(raw, dekUser) || scrub.Contains(raw, key) {
		t.Fatalf("grant JSON has a key: %s", raw)
	}
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(disk, dekOrg) || bytes.Contains(disk, dekUser) {
		t.Fatal("owner DEK plaintext on disk")
	}
}

func TestSQLiteLegacyMasterSealedSecretsRewrap(t *testing.T) {
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
	secret := Secret("sk_legacy_must_survive")
	blob, err := crypto.Seal(key, secret)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec(`INSERT INTO items(id, org_id, name, kind, owner_kind, owner_id, uris, secret, has_totp)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		"stripe", "org", "stripe", protocol.ItemAPIKey, protocol.OwnerOrg, "org", "[]", blob, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := OpenSQLite(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.Secret("stripe")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(secret) {
		t.Fatalf("got %q", got)
	}
	var sealed []byte
	if err := s2.db.QueryRow(`SELECT secret FROM items WHERE id=?`, "stripe").Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.Open(key, sealed); err == nil {
		t.Fatal("legacy secret still sealed with master")
	}
}

func TestSQLiteArchiveHistoryFileNoPlaintext(t *testing.T) {
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

	body := []byte("FILE_PLAINTEXT_MUST_NOT_HIT_DISK")
	blob, err := material.PackFile("note.txt", "text/plain", body)
	if err != nil {
		t.Fatal(err)
	}
	item := protocol.Item{
		ID:      "note",
		OrgID:   "org",
		Name:    "note",
		Kind:    protocol.ItemFile,
		Owner:   protocol.Owner{Kind: protocol.OwnerOrg, ID: "org"},
		HasFile: true,
		Tags:    []string{"docs"},
	}
	if err := s.PutItem(item, Secret(blob)); err != nil {
		t.Fatal(err)
	}
	first := Secret("sk_live_VERSION_ONE")
	api := protocol.Item{
		ID:    "stripe",
		OrgID: "org",
		Name:  "stripe",
		Kind:  protocol.ItemAPIKey,
		Owner: protocol.Owner{Kind: protocol.OwnerOrg, ID: "org"},
	}
	if err := s.PutItem(api, first); err != nil {
		t.Fatal(err)
	}
	if err := s.PutItem(api, Secret("sk_live_VERSION_TWO")); err != nil {
		t.Fatal(err)
	}
	vs, err := s.Versions("stripe")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 {
		t.Fatalf("versions=%d", len(vs))
	}
	if err := s.RestoreVersion("stripe", vs[0].ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.Secret("stripe")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(first) {
		t.Fatalf("restored %q", got)
	}
	if err := s.ArchiveItem("stripe"); err != nil {
		t.Fatal(err)
	}
	listed, err := s.ListItems()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != "note" {
		t.Fatalf("%+v", listed)
	}
	archived, err := s.Item("stripe")
	if err != nil {
		t.Fatal(err)
	}
	if !archived.Archived {
		t.Fatal("expected archived")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, body) || bytes.Contains(raw, first) {
		t.Fatal("plaintext on disk")
	}
	sec, err := s.Secret("note")
	if err != nil {
		t.Fatal(err)
	}
	file, err := material.FileBytes(material.Unpack(sec))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(file, body) {
		t.Fatalf("%q", file)
	}
	if err := s.DeleteItem("stripe"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Item("stripe"); err != ErrNotFound {
		t.Fatalf("deleted: %v", err)
	}
}
