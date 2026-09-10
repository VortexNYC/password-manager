package fill

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/scrub"
)

const secret = "sk_live_FILL_SECRET"

type client struct {
	pub, priv *[32]byte
	host      [32]byte
	id        string
	idKey     string
}

func newClient(t *testing.T) *client {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	idPub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &client{
		pub:   pub,
		priv:  priv,
		id:    "client-1",
		idKey: base64.StdEncoding.EncodeToString(idPub[:]),
	}
}

func (c *client) handshake(t *testing.T, h *Host) {
	t.Helper()
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope{
		Action:    "change-public-keys",
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		ClientID:  c.id,
		PublicKey: base64.StdEncoding.EncodeToString(c.pub[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	var got envelope
	if err := json.Unmarshal(h.Handle(raw), &got); err != nil {
		t.Fatal(err)
	}
	if got.PublicKey == "" {
		t.Fatalf("%+v", got)
	}
	k, err := b64key(got.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	c.host = k
}

func (c *client) send(t *testing.T, h *Host, inner []byte) []byte {
	t.Helper()
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	boxed := box.Seal(nil, inner, &nonce, &c.host, c.priv)
	raw, err := json.Marshal(envelope{
		Action:   "get-logins",
		Message:  base64.StdEncoding.EncodeToString(boxed),
		Nonce:    base64.StdEncoding.EncodeToString(nonce[:]),
		ClientID: c.id,
	})
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(h.Handle(raw), &env); err != nil {
		t.Fatal(err)
	}
	n, err := b64nonce(env.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	plain, ok := box.Open(nil, mustB64(env.Message), &n, &c.host, c.priv)
	if !ok {
		t.Fatal("decrypt failed")
	}
	return plain
}

func vault(t *testing.T) *app.App {
	t.Helper()
	a, err := app.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.AddItem("stripe", "https://dashboard.stripe.com", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestGetLoginsFillsMatchingURI(t *testing.T) {
	a := vault(t)
	h := New(a)
	c := newClient(t)
	c.handshake(t, h)
	assoc, err := json.Marshal(map[string]string{"action": "associate", "key": c.idKey, "idKey": c.idKey})
	if err != nil {
		t.Fatal(err)
	}
	var assocGot map[string]string
	if err := json.Unmarshal(c.send(t, h, assoc), &assocGot); err != nil {
		t.Fatal(err)
	}
	if assocGot["success"] != "true" || assocGot["id"] != assocID {
		t.Fatalf("%v", assocGot)
	}

	req, err := json.Marshal(struct {
		Action string     `json:"action"`
		URL    string     `json:"url"`
		Keys   []assocKey `json:"keys"`
	}{
		Action: "get-logins",
		URL:    "https://dashboard.stripe.com/login",
		Keys:   []assocKey{{ID: assocID, Key: c.idKey}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got loginReply
	if err := json.Unmarshal(c.send(t, h, req), &got); err != nil {
		t.Fatal(err)
	}
	if got.Success != "true" || got.Count != "1" || len(got.Entries) != 1 {
		t.Fatalf("%+v", got)
	}
	if got.Entries[0].Password != secret {
		t.Fatal("fill did not write the password to the extension")
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
		t.Fatal("item list leaked the secret")
	}
}

func TestGetLoginsWrongHostEmpty(t *testing.T) {
	a := vault(t)
	h := New(a)
	c := newClient(t)
	c.handshake(t, h)
	inner, _ := json.Marshal(map[string]string{"action": "associate", "key": c.idKey, "idKey": c.idKey})
	_ = c.send(t, h, inner)
	req, _ := json.Marshal(struct {
		Action string     `json:"action"`
		URL    string     `json:"url"`
		Keys   []assocKey `json:"keys"`
	}{Action: "get-logins", URL: "https://evil.example", Keys: []assocKey{{ID: assocID, Key: c.idKey}}})
	var got loginReply
	if err := json.Unmarshal(c.send(t, h, req), &got); err != nil {
		t.Fatal(err)
	}
	if got.Count != "0" || len(got.Entries) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestGetLoginsNeedsAssociate(t *testing.T) {
	a := vault(t)
	h := New(a)
	c := newClient(t)
	c.handshake(t, h)
	req, _ := json.Marshal(struct {
		Action string     `json:"action"`
		URL    string     `json:"url"`
		Keys   []assocKey `json:"keys"`
	}{Action: "get-logins", URL: "https://dashboard.stripe.com", Keys: []assocKey{{ID: assocID, Key: c.idKey}}})
	var got map[string]string
	if err := json.Unmarshal(c.send(t, h, req), &got); err != nil {
		t.Fatal(err)
	}
	if got["success"] != "false" {
		t.Fatalf("%v", got)
	}
}

func TestNativeFramingRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	msg := []byte(`{"action":"change-public-keys"}`)
	if err := Write(&buf, msg); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("%s", got)
	}
}

func TestInstallWritesManifestsNotExtension(t *testing.T) {
	user := t.TempDir()
	vaultDir := t.TempDir()
	bin := filepath.Join(t.TempDir(), "password-manager")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Install(bin, vaultDir, user); err != nil {
		t.Fatal(err)
	}
	chrome := filepath.Join(user, "Library/Application Support/Google/Chrome/NativeMessagingHosts", NativeHostName+".json")
	raw, err := os.ReadFile(chrome)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(NativeHostName)) {
		t.Fatal(string(raw))
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("secret in manifest")
	}
	shim, err := os.ReadFile(filepath.Join(vaultDir, "native-host"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(shim, []byte(" fill ")) {
		t.Fatalf("%s", shim)
	}
}

func TestGetTOTPMintsCodeNotSeed(t *testing.T) {
	const seed = "JBSWY3DPEHPK3PXP"
	a, err := app.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.PutItem(app.ItemOpts{Name: "stripe", URI: "https://dashboard.stripe.com", Token: []byte(secret), TOTPSeed: []byte(seed)}); err != nil {
		t.Fatal(err)
	}
	h := New(a)
	c := newClient(t)
	c.handshake(t, h)
	inner, _ := json.Marshal(map[string]string{"action": "associate", "key": c.idKey, "idKey": c.idKey})
	_ = c.send(t, h, inner)
	req, _ := json.Marshal(map[string]string{"action": "get-totp", "uuid": "stripe"})
	var got map[string]string
	if err := json.Unmarshal(c.send(t, h, req), &got); err != nil {
		t.Fatal(err)
	}
	if got["success"] != "true" || len(got["totp"]) != 6 {
		t.Fatalf("%v", got)
	}
	if got["totp"] == seed {
		t.Fatal("returned the seed")
	}
}

func TestInstallOriginBakesOriginNotToken(t *testing.T) {
	user := t.TempDir()
	vaultDir := t.TempDir()
	bin := filepath.Join(t.TempDir(), "password-manager")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := InstallOrigin(bin, vaultDir, user, "https://veil.nyc"); err != nil {
		t.Fatal(err)
	}
	shim, err := os.ReadFile(filepath.Join(vaultDir, "native-host"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(shim, []byte("PWM_ORIGIN=\"https://veil.nyc\"")) {
		t.Fatalf("%s", shim)
	}
	if !bytes.Contains(shim, []byte("PWM_HUMAN_TOKEN_FILE")) {
		t.Fatalf("shim missing human token file: %s", shim)
	}
	if bytes.Contains(shim, []byte(secret)) {
		t.Fatal("token in shim")
	}
}

func TestGetLoginsFromOrigin(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer human" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/v1/fill/logins" {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"entries":[{"login":"stripe","name":"stripe","password":"sk_live_FILL_SECRET","uuid":"stripe"}]}`)
	}))
	t.Cleanup(origin.Close)
	h := NewOrigin(t.TempDir(), origin.URL, "human")
	c := newClient(t)
	c.handshake(t, h)
	inner, _ := json.Marshal(map[string]string{"action": "associate", "key": c.idKey, "idKey": c.idKey})
	_ = c.send(t, h, inner)
	req, _ := json.Marshal(struct {
		Action string     `json:"action"`
		URL    string     `json:"url"`
		Keys   []assocKey `json:"keys"`
	}{Action: "get-logins", URL: "https://dashboard.stripe.com", Keys: []assocKey{{ID: assocID, Key: c.idKey}}})
	var got loginReply
	if err := json.Unmarshal(c.send(t, h, req), &got); err != nil {
		t.Fatal(err)
	}
	if got.Success != "true" || len(got.Entries) != 1 || got.Entries[0].Password != secret {
		t.Fatalf("%+v", got)
	}
}

func TestFillDoesNotAddAgentSurface(t *testing.T) {
	a := vault(t)
	if _, err := a.AddAgent("claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddGrant("claude", "stripe", protocol.Level2); err != nil {
		t.Fatal(err)
	}
	items, err := a.ItemsForAgent("claude")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatal(string(raw))
	}
}
