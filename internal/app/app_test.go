package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	"github.com/vortexnyc/password-manager/internal/store"
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
	if got[0].Login != "" {
		t.Fatalf("unset login must stay empty, not item name: %+v", got)
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

func TestFillLoginsUsesEnvelopeLoginNotName(t *testing.T) {
	const login = "stripe@example.com"
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.PutItem(ItemOpts{
		Name:  "stripe",
		URI:   "https://dashboard.stripe.com",
		Token: []byte(secret),
		Login: login,
	}); err != nil {
		t.Fatal(err)
	}
	human := protocol.Principal{Kind: protocol.PrincipalHuman, ID: DefaultHuman, OrgID: a.OrgID}
	got, err := a.FillLogins(human, "https://dashboard.stripe.com/login")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Login != login || got[0].Name != "stripe" || got[0].Password != secret {
		t.Fatalf("%+v", got)
	}
	if _, err := a.UpdateItem("stripe", nil, nil, nil, "other@example.com"); err != nil {
		t.Fatal(err)
	}
	got, err = a.FillLogins(human, "https://dashboard.stripe.com/login")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Login != "other@example.com" || got[0].Password != secret {
		t.Fatalf("update rotated or missed login: %+v", got)
	}
	items, err := a.Store.ListItems()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatal("item list leaked secret")
	}
	if len(items) != 1 || items[0].Login != "other@example.com" {
		t.Fatalf("login should be on the item: %+v", items)
	}
}

type secretProbe struct {
	store.Store
	n int
}

func (p *secretProbe) Secret(id string) (store.Secret, error) {
	p.n++
	return p.Store.Secret(id)
}

func TestMatchNeverDecrypts(t *testing.T) {
	const login = "stripe@example.com"
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.PutItem(ItemOpts{
		Name:  "stripe",
		URI:   "https://dashboard.stripe.com",
		Token: []byte(secret),
		Login: login,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PutItem(ItemOpts{
		Name:  "github",
		URI:   "https://github.com",
		Token: []byte(secret),
	}); err != nil {
		t.Fatal(err)
	}
	probe := &secretProbe{Store: a.Store}
	a.Store = probe
	human := protocol.Principal{Kind: protocol.PrincipalHuman, ID: DefaultHuman, OrgID: a.OrgID}
	got, err := a.Match(human, "https://dashboard.stripe.com/login")
	if err != nil {
		t.Fatal(err)
	}
	if probe.n != 0 {
		t.Fatalf("Match called Secret %d times", probe.n)
	}
	if len(got) != 1 || got[0].Name != "stripe" || got[0].Login != login || got[0].ID != "stripe" || !got[0].Kind.Injects() {
		t.Fatalf("%+v", got)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatal("match leaked secret")
	}
	empty, err := a.Match(human, "https://github.com/login")
	if err != nil {
		t.Fatal(err)
	}
	if probe.n != 0 {
		t.Fatalf("Match called Secret %d times", probe.n)
	}
	if len(empty) != 1 || empty[0].Name != "github" || empty[0].Login != "" {
		t.Fatalf("empty login must be honest: %+v", empty)
	}
	miss, err := a.Match(human, "https://evil.example/login")
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong host %+v", miss)
	}
	if _, err := a.Match(protocol.Principal{Kind: protocol.PrincipalAgent, ID: "claude", OrgID: a.OrgID}, "https://dashboard.stripe.com"); err == nil {
		t.Fatal("agent match")
	}
}

func TestFillLoginDecryptsOne(t *testing.T) {
	const loginA = "a@example.com"
	const loginB = "b@example.com"
	secretA := secret + "-a"
	secretB := secret + "-b"
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.PutItem(ItemOpts{Name: "stripe-a", URI: "https://dashboard.stripe.com", Token: []byte(secretA), Login: loginA}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PutItem(ItemOpts{Name: "stripe-b", URI: "https://dashboard.stripe.com", Token: []byte(secretB), Login: loginB}); err != nil {
		t.Fatal(err)
	}
	human := protocol.Principal{Kind: protocol.PrincipalHuman, ID: DefaultHuman, OrgID: a.OrgID}
	probe := &secretProbe{Store: a.Store}
	a.Store = probe
	all, err := a.FillLogins(human, "https://dashboard.stripe.com/login")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("url form %+v", all)
	}
	if probe.n != 2 {
		t.Fatalf("url form Secret %d", probe.n)
	}
	probe.n = 0
	one, err := a.FillLogin(human, "stripe-a", false)
	if err != nil {
		t.Fatal(err)
	}
	if probe.n != 1 {
		t.Fatalf("uuid form Secret %d", probe.n)
	}
	if one.UUID != "stripe-a" || one.Login != loginA || one.Password != secretA {
		t.Fatalf("%+v", one)
	}
	if one.Password == secretB || strings.Contains(one.Password, secretB) {
		t.Fatal("decrypted the other item")
	}
	if _, err := a.FillLogin(human, "missing", false); err == nil {
		t.Fatal("missing uuid")
	}
	if _, err := a.FillLogin(protocol.Principal{Kind: protocol.PrincipalAgent, ID: "claude", OrgID: a.OrgID}, "stripe-a", false); err == nil {
		t.Fatal("agent fill")
	}
}

func TestFillLoginMintTotp(t *testing.T) {
	const seed = "JBSWY3DPEHPK3PXP"
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.PutItem(ItemOpts{
		Name:     "stripe",
		URI:      "https://dashboard.stripe.com",
		Token:    []byte(secret),
		TOTPSeed: []byte(seed),
	}); err != nil {
		t.Fatal(err)
	}
	human := protocol.Principal{Kind: protocol.PrincipalHuman, ID: DefaultHuman, OrgID: a.OrgID}
	star, err := a.FillLogin(human, "stripe", false)
	if err != nil {
		t.Fatal(err)
	}
	if star.TOTP != "*" || star.Password != secret {
		t.Fatalf("%+v", star)
	}
	got, err := a.FillLogin(human, "stripe", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.TOTP) != 6 || got.TOTP == seed || got.TOTP == "*" {
		t.Fatalf("mint %+v", got)
	}
	if got.Password != secret {
		t.Fatal("mint totp dropped the password")
	}
	if _, err := a.PutItem(ItemOpts{Name: "github", URI: "https://github.com", Token: []byte(secret)}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.FillLogin(human, "github", true); err == nil {
		t.Fatal("mint without seed")
	}
}

func TestUpdateItemURIAddsWithoutDropping(t *testing.T) {
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.PutItem(ItemOpts{
		Name:  "github",
		URI:   "https://api.github.com",
		Token: []byte(secret),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := a.UpdateItem("github", nil, []string{"https://github.com"}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.URIs) != 2 || got.URIs[0] != "https://api.github.com" || got.URIs[1] != "https://github.com" {
		t.Fatalf("add dropped a host: %+v", got.URIs)
	}
	again, err := a.UpdateItem("github", nil, []string{"https://github.com"}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(again.URIs) != 2 {
		t.Fatalf("add duplicated: %+v", again.URIs)
	}
	replaced, err := a.UpdateItem("github", []string{"https://github.com"}, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(replaced.URIs) != 1 || replaced.URIs[0] != "https://github.com" {
		t.Fatalf("uris did not replace: %+v", replaced.URIs)
	}
}

const familyHuman = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

type fakeMembers struct {
	owners  map[string]bool
	members map[string]bool
}

func (f fakeMembers) IsMember(_ context.Context, id string) (bool, error) {
	return f.members[id], nil
}

func (f fakeMembers) IsOwner(_ context.Context, id string) (bool, error) {
	return f.owners[id], nil
}

func TestHumanGrantFillIsNotAFamilyVault(t *testing.T) {
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.Members = fakeMembers{
		members: map[string]bool{familyHuman: true, "cccccccc-cccc-4ccc-8ccc-cccccccccccc": true},
		owners:  map[string]bool{},
	}
	if _, err := a.AddItem("stripe", "https://dashboard.stripe.com", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PutItem(ItemOpts{
		Name:     "gmail",
		URI:      "https://accounts.google.com",
		Token:    []byte(secret),
		TOTPSeed: []byte("JBSWY3DPEHPK3PXP"),
	}); err != nil {
		t.Fatal(err)
	}
	owner := protocol.Principal{Kind: protocol.PrincipalHuman, ID: DefaultHuman, OrgID: a.OrgID}
	member := protocol.Principal{Kind: protocol.PrincipalHuman, ID: familyHuman, OrgID: a.OrgID}
	stranger := protocol.Principal{Kind: protocol.PrincipalHuman, ID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", OrgID: a.OrgID}
	got, err := a.FillLogins(owner, "https://dashboard.stripe.com/login")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Password != secret {
		t.Fatalf("owner fill %+v", got)
	}
	got, err = a.FillLogins(member, "https://dashboard.stripe.com/login")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("member without grant is a family vault: %+v", got)
	}
	matched, err := a.Match(member, "https://dashboard.stripe.com/login")
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 0 {
		t.Fatalf("member match without grant: %+v", matched)
	}
	if _, err := a.GrantUntil(familyHuman, "stripe", protocol.Level2, nil); err != nil {
		t.Fatal(err)
	}
	got, err = a.FillLogins(member, "https://dashboard.stripe.com/login")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Password != secret || got[0].Name != "stripe" {
		t.Fatalf("granted fill %+v", got)
	}
	matched, err = a.Match(member, "https://dashboard.stripe.com/login")
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 1 || matched[0].Name != "stripe" {
		t.Fatalf("granted match %+v", matched)
	}
	listed, err := a.ItemsForPrincipal(member)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(listed)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatal("member list leaked secret")
	}
	if len(listed) != 1 || listed[0].Name != "stripe" {
		t.Fatalf("member list %+v", listed)
	}
	got, err = a.FillLogins(stranger, "https://dashboard.stripe.com/login")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("ungranted member %+v", got)
	}
	if _, err := a.FillTOTP(member, "gmail", time.Now()); err == nil {
		t.Fatal("totp without grant")
	}
	if _, err := a.GrantUntil(familyHuman, "gmail", protocol.Level2, nil); err != nil {
		t.Fatal(err)
	}
	code, err := a.FillTOTP(member, "gmail", time.Now())
	if err != nil || len(code) != 6 {
		t.Fatalf("granted totp %q %v", code, err)
	}
	past := time.Now().Add(-time.Second)
	if _, err := a.GrantUntil(familyHuman, "stripe", protocol.Level2, &past); err != nil {
		t.Fatal(err)
	}
	got, err = a.FillLogins(member, "https://dashboard.stripe.com/login")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expired grant %+v", got)
	}
	if _, err := a.GrantUntil("dddddddd-dddd-4ddd-8ddd-dddddddddddd", "stripe", protocol.Level2, nil); err == nil {
		t.Fatal("granted to non-member")
	}
}

func TestFillPasskeyHumanOnlyNoListLeak(t *testing.T) {
	a, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	human := protocol.Principal{Kind: protocol.PrincipalHuman, ID: DefaultHuman, OrgID: a.OrgID}
	create, err := json.Marshal(map[string]any{
		"challenge": "dGVzdGNoYWxsZW5nZQ",
		"rp":        map[string]string{"id": "github.com", "name": "GitHub"},
		"user":      map[string]string{"id": "dXNlcg", "name": "ada", "displayName": "Ada"},
		"pubKeyCredParams": []map[string]any{
			{"type": "public-key", "alg": -7},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.FillPasskeyRegister(human, "https://github.com", create, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(resp, []byte("BEGIN")) {
		t.Fatal("register leaked pem")
	}
	if _, err := a.AddAgent("claude"); err != nil {
		t.Fatal(err)
	}
	agent := protocol.Principal{Kind: protocol.PrincipalAgent, ID: "claude", OrgID: a.OrgID}
	if _, err := a.FillPasskeyGet(agent, "https://github.com", create); err == nil {
		t.Fatal("agent fill passkey")
	}
	items, err := a.ItemsForPrincipal(human)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(listed, []byte("BEGIN")) || bytes.Contains(listed, []byte("passkey_pem")) {
		t.Fatal("list leaked passkey")
	}
	logins, err := a.FillLogins(human, "https://github.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(logins) != 0 {
		t.Fatalf("password fill returned passkey %+v", logins)
	}
}

func TestSessionMapsToAgentAndExpires(t *testing.T) {
	a, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.AddAgent("claude"); err != nil {
		t.Fatal(err)
	}
	owner := protocol.Principal{Kind: protocol.PrincipalHuman, ID: DefaultHuman, OrgID: a.OrgID}
	sess, token, err := a.CreateSession(owner, "claude", 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if sess.AgentID != "claude" || !IsSessionToken(token) {
		t.Fatalf("%+v %s", sess, token)
	}
	p, err := a.PrincipalFromSession(token)
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != protocol.PrincipalAgent || p.ID != "claude" {
		t.Fatalf("%+v", p)
	}
	agent, err := a.PrincipalFromOIDC(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if agent.ID != "claude" {
		t.Fatalf("%+v", agent)
	}
	if _, _, err := a.CreateSession(p, "claude", time.Minute); !errors.Is(err, ErrForbidden) {
		t.Fatalf("agent minted session: %v", err)
	}
	listed, err := a.ListSessions(owner)
	if err != nil || len(listed) != 1 || listed[0].ID != sess.ID {
		t.Fatalf("%+v %v", listed, err)
	}
	time.Sleep(400 * time.Millisecond)
	if _, err := a.PrincipalFromSession(token); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expired: %v", err)
	}
	listed, err = a.ListSessions(owner)
	if err != nil || len(listed) != 0 {
		t.Fatalf("expired still listed %+v", listed)
	}
}
