// Package fill is the keepassxc-browser native host. We speak their wire.
// We do not vendor the extension and we do not use KeePassXC as the vault.
//
// Wire: Chrome native messaging (uint32 LE + JSON) and TweetNaCl box
// (golang.org/x/crypto/nacl/box). Fill writes into the page. The password
// never returns on an agent surface.
package fill

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/grant"
	"github.com/vortexnyc/password-manager/internal/material"
)

const (
	Version        = "2.7.0"
	NativeHostName = "org.keepassxc.keepassxc_browser"
	maxMsg         = 1 << 20
	assocFile      = "fill-assoc.json"
	assocID        = "password-manager"
)

type Host struct {
	App *app.App

	mu       sync.Mutex
	sessions map[string]*session
	assocKey string
}

type session struct {
	client [32]byte
	pub    [32]byte
	priv   [32]byte
}

type envelope struct {
	Action    string `json:"action"`
	Message   string `json:"message,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	ClientID  string `json:"clientID,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`
}

func New(a *app.App) *Host {
	h := &Host{App: a, sessions: map[string]*session{}}
	h.loadAssoc()
	return h
}

func (h *Host) Serve(in io.Reader, out io.Writer) error {
	for {
		raw, err := Read(in)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if err := Write(out, h.Handle(raw)); err != nil {
			return err
		}
	}
}

func Read(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
		return nil, err
	}
	if n == 0 || n > maxMsg {
		return nil, fmt.Errorf("fill: bad frame")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func Write(w io.Writer, raw []byte) error {
	if err := binary.Write(w, binary.LittleEndian, uint32(len(raw))); err != nil {
		return err
	}
	_, err := w.Write(raw)
	return err
}

func (h *Host) Handle(raw []byte) []byte {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return []byte(`{"success":"false","error":"bad json"}`)
	}
	switch env.Action {
	case "change-public-keys":
		return h.changeKeys(env)
	default:
		return h.encrypted(env)
	}
}

func (h *Host) changeKeys(env envelope) []byte {
	pub, err := b64key(env.PublicKey)
	if err != nil || env.ClientID == "" {
		return []byte(`{"action":"change-public-keys","success":"false"}`)
	}
	ourPub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return []byte(`{"action":"change-public-keys","success":"false"}`)
	}
	h.mu.Lock()
	h.sessions[env.ClientID] = &session{client: pub, pub: *ourPub, priv: *priv}
	h.mu.Unlock()
	out := envelope{
		Action:    "change-public-keys",
		PublicKey: base64.StdEncoding.EncodeToString(ourPub[:]),
	}
	raw, _ := json.Marshal(struct {
		Action    string `json:"action"`
		Version   string `json:"version"`
		PublicKey string `json:"publicKey"`
		Success   string `json:"success"`
	}{
		Action:    out.Action,
		Version:   Version,
		PublicKey: out.PublicKey,
		Success:   "true",
	})
	return raw
}

func (h *Host) encrypted(env envelope) []byte {
	h.mu.Lock()
	s := h.sessions[env.ClientID]
	h.mu.Unlock()
	if s == nil {
		return []byte(`{"success":"false","error":"no session"}`)
	}
	nonce, err := b64nonce(env.Nonce)
	if err != nil {
		return fail(env.Action, "bad nonce")
	}
	plain, ok := box.Open(nil, mustB64(env.Message), &nonce, &s.client, &s.priv)
	if !ok {
		return fail(env.Action, "decrypt")
	}
	var inner struct {
		Action string     `json:"action"`
		URL    string     `json:"url"`
		ID     string     `json:"id"`
		Key    string     `json:"key"`
		IDKey  string     `json:"idKey"`
		UUID   string     `json:"uuid"`
		Keys   []assocKey `json:"keys"`
	}
	if err := json.Unmarshal(plain, &inner); err != nil {
		return h.reply(s, nonce, mustJSON(failMap("bad message")))
	}
	var body map[string]string
	switch inner.Action {
	case "get-databasehash":
		body = h.hashBody()
	case "associate":
		body = h.associate(inner.IDKey, inner.Key)
	case "test-associate":
		body = h.testAssociate(inner.ID, inner.Key)
	case "get-logins":
		if !h.knownKey(inner.Keys) {
			return h.reply(s, nonce, mustJSON(failMap("not associated")))
		}
		return h.reply(s, nonce, mustJSON(h.logins(inner.URL)))
	case "get-totp":
		body = h.totp(inner.UUID)
	default:
		body = failMap("unknown action")
	}
	return h.reply(s, nonce, mustJSON(body))
}

type assocKey struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

func (h *Host) hashBody() map[string]string {
	return map[string]string{
		"action":  "hash",
		"hash":    h.hash(),
		"version": Version,
		"success": "true",
	}
}

func (h *Host) associate(idKey, key string) map[string]string {
	if idKey == "" {
		idKey = key
	}
	if idKey == "" {
		return failMap("missing key")
	}
	h.mu.Lock()
	h.assocKey = idKey
	h.mu.Unlock()
	h.saveAssoc(idKey)
	return map[string]string{
		"hash":    h.hash(),
		"version": Version,
		"success": "true",
		"id":      assocID,
	}
}

func (h *Host) testAssociate(id, key string) map[string]string {
	h.mu.Lock()
	want := h.assocKey
	h.mu.Unlock()
	if want == "" || key != want || (id != "" && id != assocID) {
		return failMap("not associated")
	}
	return map[string]string{
		"version": Version,
		"hash":    h.hash(),
		"id":      assocID,
		"success": "true",
	}
}

type loginReply struct {
	Count   string       `json:"count"`
	Entries []loginEntry `json:"entries"`
	Nonce   string       `json:"nonce,omitempty"`
	Success string       `json:"success"`
	Hash    string       `json:"hash"`
	Version string       `json:"version"`
}

type loginEntry struct {
	Login    string `json:"login"`
	Name     string `json:"name"`
	Password string `json:"password"`
	UUID     string `json:"uuid"`
}

func (h *Host) logins(rawURL string) loginReply {
	items, err := h.App.Store.ListItems()
	if err != nil {
		return loginReply{Count: "0", Entries: []loginEntry{}, Success: "false", Hash: h.hash(), Version: Version}
	}
	var entries []loginEntry
	for _, item := range items {
		if !grant.HostAllowed(item, rawURL) {
			continue
		}
		sec, err := h.App.Store.Secret(item.ID)
		if err != nil {
			continue
		}
		env := material.Unpack([]byte(sec))
		pass := env.Token
		if pass == "" {
			pass = string(sec)
		}
		login := item.Name
		entries = append(entries, loginEntry{
			Login:    login,
			Name:     item.Name,
			Password: pass,
			UUID:     item.ID,
		})
	}
	if entries == nil {
		entries = []loginEntry{}
	}
	return loginReply{
		Count:   strconv.Itoa(len(entries)),
		Entries: entries,
		Success: "true",
		Hash:    h.hash(),
		Version: Version,
	}
}

func (h *Host) totp(uuid string) map[string]string {
	if uuid == "" {
		return failMap("missing uuid")
	}
	item, err := h.App.Store.Item(uuid)
	if err != nil || !item.HasTOTP {
		return failMap("no totp")
	}
	sec, err := h.App.Store.Secret(item.ID)
	if err != nil {
		return failMap("no totp")
	}
	env := material.Unpack([]byte(sec))
	code, err := material.Mint(env.TOTP, time.Now())
	if err != nil || code == "" {
		return failMap("no totp")
	}
	return map[string]string{
		"totp":    code,
		"version": Version,
		"success": "true",
	}
}

func (h *Host) knownKey(keys []assocKey) bool {
	h.mu.Lock()
	want := h.assocKey
	h.mu.Unlock()
	if want == "" {
		return false
	}
	for _, k := range keys {
		if k.Key == want {
			return true
		}
	}
	return false
}

func (h *Host) hash() string {
	sum := sha256.Sum256([]byte("pwm:" + h.App.OrgID))
	return hex.EncodeToString(sum[:])
}

func (h *Host) reply(s *session, nonce [24]byte, plain []byte) []byte {
	next := bumpNonce(nonce)
	boxed := box.Seal(nil, plain, &next, &s.client, &s.priv)
	raw, err := json.Marshal(envelope{
		Action:  "get-logins",
		Message: base64.StdEncoding.EncodeToString(boxed),
		Nonce:   base64.StdEncoding.EncodeToString(next[:]),
	})
	if err != nil {
		return fail("", "marshal")
	}
	return raw
}

func bumpNonce(n [24]byte) [24]byte {
	c := 1
	for i := 0; i < 24; i++ {
		c += int(n[i])
		n[i] = byte(c)
		c >>= 8
	}
	return n
}

func fail(action, msg string) []byte {
	raw, _ := json.Marshal(map[string]string{"action": action, "success": "false", "error": msg})
	return raw
}

func failMap(msg string) map[string]string {
	return map[string]string{"success": "false", "error": msg}
}

func b64key(s string) ([32]byte, error) {
	var out [32]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("fill: key")
	}
	copy(out[:], b)
	return out, nil
}

func b64nonce(s string) ([24]byte, error) {
	var out [24]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 24 {
		return out, fmt.Errorf("fill: nonce")
	}
	copy(out[:], b)
	return out, nil
}

func mustB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func mustJSON[T loginReply | map[string]string](v T) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"success":"false"}`)
	}
	return raw
}

type assocDisk struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

func (h *Host) loadAssoc() {
	if h.App == nil || h.App.Dir == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(h.App.Dir, assocFile))
	if err != nil {
		return
	}
	var d assocDisk
	if err := json.Unmarshal(raw, &d); err != nil || d.Key == "" {
		return
	}
	h.assocKey = d.Key
}

func (h *Host) saveAssoc(key string) {
	if h.App == nil || h.App.Dir == "" {
		return
	}
	raw, err := json.Marshal(assocDisk{ID: assocID, Key: key})
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(h.App.Dir, assocFile), raw, 0o600)
}

func ChromeOrigin() string {
	return "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/"
}

func FirefoxID() string {
	return "keepassxc-browser@keepassxc.org"
}

func ManifestChrome(hostPath string) []byte {
	raw, _ := json.MarshalIndent(struct {
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		Path           string   `json:"path"`
		Type           string   `json:"type"`
		AllowedOrigins []string `json:"allowed_origins"`
	}{
		Name:           NativeHostName,
		Description:    "password-manager fill host",
		Path:           hostPath,
		Type:           "stdio",
		AllowedOrigins: []string{ChromeOrigin()},
	}, "", "  ")
	return append(raw, '\n')
}

func ManifestFirefox(hostPath string) []byte {
	raw, _ := json.MarshalIndent(struct {
		Name              string   `json:"name"`
		Description       string   `json:"description"`
		Path              string   `json:"path"`
		Type              string   `json:"type"`
		AllowedExtensions []string `json:"allowed_extensions"`
	}{
		Name:              NativeHostName,
		Description:       "password-manager fill host",
		Path:              hostPath,
		Type:              "stdio",
		AllowedExtensions: []string{FirefoxID()},
	}, "", "  ")
	return append(raw, '\n')
}

func Shim(bin, home string) string {
	return "#!/bin/sh\nexec \"" + strings.ReplaceAll(bin, `"`, `\"`) + "\" fill --home \"" + strings.ReplaceAll(home, `"`, `\"`) + "\"\n"
}
