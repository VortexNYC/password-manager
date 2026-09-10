package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vortexnyc/password-manager/internal/broker"
	"github.com/vortexnyc/password-manager/internal/device"
	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/scrub"
)

const secret = "sk_live_APP_TEST_SECRET"

func TestOpenOrInitCreatesVaultWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	a, err := OpenOrInit(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := os.Stat(filepath.Join(dir, dbFile)); err != nil {
		t.Fatal(err)
	}
	b, err := OpenOrInit(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
}

func TestOpenEmptyDirIsTheRailwayMasterKeyMiss(t *testing.T) {
	dir := t.TempDir()
	_, err := Open(dir)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "master.key") {
		t.Fatalf("got %v", err)
	}
}

func TestOpenOrInitStrayVaultDBWithoutKeys(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, dbFile), []byte("not-a-vault"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := OpenOrInit(dir)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "no such file") {
		t.Fatalf("misleading Railway crash: %v", err)
	}
	if !strings.Contains(err.Error(), dbFile) {
		t.Fatalf("got %v", err)
	}
}

func TestInitUseApprovePersists(t *testing.T) {
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.OrgID != protocol.LocalOrgID {
		t.Fatalf("org %q", a.OrgID)
	}
	if _, err := os.Stat(filepath.Join(dir, "master.key")); err == nil {
		t.Fatal("plaintext master.key after init")
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"echo":"`+r.Header.Get("Authorization")+`"}`)
	}))
	t.Cleanup(upstream.Close)

	if _, err := a.AddItem("stripe", upstream.URL, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddAgent("claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddGrant("claude", "stripe", protocol.Level1); err != nil {
		t.Fatal(err)
	}

	got, err := a.Use(context.Background(), "claude", "stripe", http.MethodGet, upstream.URL+"/v1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != protocol.DecisionNeedApproval {
		t.Fatalf("%+v", got)
	}
	if err := broker.AssertNoSecret(got, []byte(secret)); err != nil {
		t.Fatal(err)
	}

	if _, err := a.Approve("claude:stripe", time.Minute); err != nil {
		t.Fatal(err)
	}
	got, err = a.Use(context.Background(), "claude", "stripe", http.MethodGet, upstream.URL+"/v1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != protocol.DecisionAllow {
		t.Fatalf("%+v", got)
	}
	if scrub.Contains(got.Fetch.Body, []byte(secret)) {
		t.Fatalf("leak in body: %s", got.Fetch.Body)
	}

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatal("plaintext in db after close")
	}

	a2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Close()
	items, err := a2.ItemsForAgent("claude")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Name != "stripe" {
		t.Fatalf("%+v", items)
	}
	b, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(b, []byte(secret)) {
		t.Fatal("list leaked secret")
	}

	if _, err := Init(dir); err != ErrExists {
		t.Fatalf("second init: %v", err)
	}
}

func TestArchiveHidesFromAgentAndUse(t *testing.T) {
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	t.Cleanup(upstream.Close)
	if _, err := a.AddItem("stripe", upstream.URL, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddAgent("claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddGrant("claude", "stripe", protocol.Level2); err != nil {
		t.Fatal(err)
	}
	if err := a.ArchiveItem("stripe"); err != nil {
		t.Fatal(err)
	}
	got, err := a.Use(context.Background(), "claude", "stripe", http.MethodGet, upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != protocol.DecisionDeny || got.Reason != "item_archived" {
		t.Fatalf("%+v", got)
	}
	if err := broker.AssertNoSecret(got, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	items, err := a.ItemsForAgent("claude")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("%+v", items)
	}
	if _, err := a.AddGrant("claude", "stripe", protocol.Level2); err == nil {
		t.Fatal("grant on archived")
	}
}

func TestFileItemWritesToDiskNotJSON(t *testing.T) {
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	body := []byte("FILE_APP_SECRET")
	item, err := a.PutItem(ItemOpts{Name: "note", FileName: "note.txt", File: body})
	if err != nil {
		t.Fatal(err)
	}
	if !item.HasFile || item.Kind != protocol.ItemFile {
		t.Fatalf("%+v", item)
	}
	raw, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(raw, body) {
		t.Fatalf("item json leaked: %s", raw)
	}
	dest := filepath.Join(dir, "out.txt")
	if err := a.WriteFile("note", dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("%q", got)
	}
}

func TestGrantUntilExpires(t *testing.T) {
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	t.Cleanup(upstream.Close)
	if _, err := a.AddItem("stripe", upstream.URL, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddAgent("claude"); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Second)
	if _, err := a.GrantUntil("claude", "stripe", protocol.Level2, &past); err != nil {
		t.Fatal(err)
	}
	got, err := a.Use(context.Background(), "claude", "stripe", http.MethodGet, upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got.Reason != "grant_expired" {
		t.Fatalf("%+v", got)
	}
}

func TestLevel2SkipsApproval(t *testing.T) {
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	t.Cleanup(upstream.Close)
	if _, err := a.AddItem("stripe", upstream.URL, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddAgent("ci"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddGrant("ci", "stripe", protocol.Level2); err != nil {
		t.Fatal(err)
	}
	got, err := a.Use(context.Background(), "ci", "stripe", http.MethodGet, upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != protocol.DecisionAllow {
		t.Fatalf("%+v", got)
	}
}

func TestApproveOIDCRequiresIssuer(t *testing.T) {
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.ApproveOIDC(context.Background(), "claude:stripe", "token", time.Minute); err == nil {
		t.Fatal("approved without a hydra issuer")
	}
}

func TestApproveRequiresOIDCWhenIssuerSet(t *testing.T) {
	t.Setenv("PWM_HYDRA_ISSUER", "http://127.0.0.1:4444")
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.AddItem("stripe", "https://example.com", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddAgent("claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddGrant("claude", "stripe", protocol.Level1); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Approve("claude:stripe", time.Minute); err == nil {
		t.Fatal("approved as planted self with hydra configured")
	}
}

func TestAddGrantDeniedForOtherOwner(t *testing.T) {
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.AddItem("stripe", "https://api.stripe.com", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	p := protocol.Principal{
		Kind:  protocol.PrincipalAgent,
		ID:    "claude",
		OrgID: a.OrgID,
		Owner: protocol.Owner{Kind: protocol.OwnerUser, ID: "someone-else"},
	}
	if err := a.Store.PutAgent(p); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddGrant("claude", "stripe", protocol.Level2); err == nil {
		t.Fatal("granted for another owner")
	}
}

func TestPlantedHumanIsSelfOnly(t *testing.T) {
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	humans, err := a.Store.ListHumans()
	if err != nil {
		t.Fatal(err)
	}
	if len(humans) != 1 || humans[0].ID != DefaultHuman {
		t.Fatalf("%+v", humans)
	}
	raw, err := json.Marshal(humans)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "@") {
		t.Fatalf("email in vault: %s", raw)
	}
}

func TestOpenMigratesLegacyMasterKey(t *testing.T) {
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddItem("stripe", "https://example.com", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	master, err := loadMaster(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir, wrapsDir)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, deviceFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyFile), master, 0o600); err != nil {
		t.Fatal(err)
	}
	a2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Close()
	if _, err := os.Stat(filepath.Join(dir, keyFile)); err == nil {
		t.Fatal("legacy master.key remains")
	}
	items, err := a2.Store.ListItems()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("%+v", items)
	}
}

func TestOfferAcceptOpensSameVaultAndBlobHasNoMaster(t *testing.T) {
	src := t.TempDir()
	a, err := Init(src)
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok:"+r.Header.Get("Authorization"))
	}))
	t.Cleanup(upstream.Close)
	if _, err := a.AddItem("stripe", upstream.URL, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddAgent("claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddGrant("claude", "stripe", protocol.Level2); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}
	master, err := loadMaster(src)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := a.Offer(pub)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(blob, master) || scrub.Contains(blob, priv) {
		t.Fatal("pairing blob leaked")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	dst := t.TempDir()
	copyVaultWithoutMaster(t, src, dst)
	if err := Accept(dst, priv, blob); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "master.key")); err == nil {
		t.Fatal("accept wrote plaintext master.key")
	}
	b, err := Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	got, err := b.Use(context.Background(), "claude", "stripe", http.MethodGet, upstream.URL+"/v1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != protocol.DecisionAllow {
		t.Fatalf("%+v", got)
	}
	if err := broker.AssertNoSecret(got, []byte(secret)); err != nil {
		t.Fatal(err)
	}
}

func copyVaultWithoutMaster(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"vault.db", "config.json"} {
		raw, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFillLoginsHumanOnly(t *testing.T) {
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.AddItem("stripe", "https://dashboard.stripe.com", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddAgent("claude"); err != nil {
		t.Fatal(err)
	}
	human := protocol.Principal{Kind: protocol.PrincipalHuman, ID: DefaultHuman, OrgID: a.OrgID}
	got, err := a.FillLogins(human, "https://dashboard.stripe.com/login")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Password != secret {
		t.Fatalf("%+v", got)
	}
	agent := protocol.Principal{Kind: protocol.PrincipalAgent, ID: "claude", OrgID: a.OrgID}
	if _, err := a.FillLogins(agent, "https://dashboard.stripe.com"); err == nil {
		t.Fatal("agent fill")
	}
	items, err := a.ItemsForPrincipal(agent)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatal("agent list leaked secret")
	}
}
