// Package fill is the native host. We speak the keepassxc-browser wire
// (slice 26 store listing, slice 31 passkeys-*). Customers get a Veil
// extension (slice 37). We do not copy that extension into this tree and
// we do not use KeePassXC as the vault.
//
// Wire: Chrome native messaging (uint32 LE + JSON) and TweetNaCl box
// (golang.org/x/crypto/nacl/box). Fill writes into the page. The password
// and passkey private key never return on an agent surface.
package fill

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/protocol"
)

const (
	Version        = "2.7.7"
	NativeHostName = "org.keepassxc.keepassxc_browser"
	maxMsg         = 1 << 20
	assocFile      = "fill-assoc.json"
	assocID        = "password-manager"
)

type Host struct {
	App    *app.App
	Dir    string
	Origin string
	Token  string

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

func NewOrigin(dir, origin, token string) *Host {
	h := &Host{Dir: dir, Origin: strings.TrimRight(origin, "/"), Token: token, sessions: map[string]*session{}}
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

func fillDebug(msg string) {
	if os.Getenv("PWM_FILL_DEBUG") == "" {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(home, ".password-manager", "fill-debug.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = f.WriteString(time.Now().Format(time.RFC3339) + " " + msg + "\n")
	_ = f.Close()
}

func (h *Host) Handle(raw []byte) []byte {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		fillDebug("bad json")
		return []byte(`{"success":"false","error":"bad json"}`)
	}
	fillDebug("action=" + env.Action + " nonce=" + env.Nonce)
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
	nonce, err := b64nonce(env.Nonce)
	if err != nil {
		return []byte(`{"action":"change-public-keys","success":"false"}`)
	}
	ourPub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return []byte(`{"action":"change-public-keys","success":"false"}`)
	}
	h.mu.Lock()
	h.sessions[env.ClientID] = &session{client: pub, pub: *ourPub, priv: *priv}
	h.mu.Unlock()
	next := bumpNonce(nonce)
	raw, _ := json.Marshal(struct {
		Action    string `json:"action"`
		Version   string `json:"version"`
		PublicKey string `json:"publicKey"`
		Nonce     string `json:"nonce"`
		Success   string `json:"success"`
	}{
		Action:    "change-public-keys",
		Version:   Version,
		PublicKey: base64.StdEncoding.EncodeToString(ourPub[:]),
		Nonce:     base64.StdEncoding.EncodeToString(next[:]),
		Success:   "true",
	})
	return raw
}

func (h *Host) encrypted(env envelope) []byte {
	h.mu.Lock()
	s := h.sessions[env.ClientID]
	h.mu.Unlock()
	if s == nil {
		fillDebug("no session")
		return []byte(`{"success":"false","error":"no session"}`)
	}
	nonce, err := b64nonce(env.Nonce)
	if err != nil {
		fillDebug("bad nonce")
		return fail(env.Action, "bad nonce")
	}
	plain, ok := box.Open(nil, mustB64(env.Message), &nonce, &s.client, &s.priv)
	if !ok {
		fillDebug("decrypt fail")
		return fail(env.Action, "decrypt")
	}
	var inner struct {
		Action         string          `json:"action"`
		URL            string          `json:"url"`
		ID             string          `json:"id"`
		Key            string          `json:"key"`
		IDKey          string          `json:"idKey"`
		UUID           string          `json:"uuid"`
		Origin         string          `json:"origin"`
		PublicKey      json.RawMessage `json:"publicKey"`
		RelatedOrigins []string        `json:"relatedOrigins"`
		Keys           []assocKey      `json:"keys"`
	}
	if err := json.Unmarshal(plain, &inner); err != nil {
		fillDebug("bad inner json")
		return h.reply(s, nonce, env.Action, mustJSON(failMap("bad message")))
	}
	fillDebug("inner=" + inner.Action)
	action := inner.Action
	if action == "" {
		action = env.Action
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
			return h.reply(s, nonce, action, mustJSON(failMap("not associated")))
		}
		return h.reply(s, nonce, action, mustJSON(h.logins(inner.URL)))
	case "get-totp":
		body = h.totp(inner.UUID)
	case "passkeys-register":
		if !h.knownKey(inner.Keys) {
			return h.reply(s, nonce, action, mustJSON(failMap("not associated")))
		}
		return h.reply(s, nonce, action, h.passkeysRegister(inner.Origin, inner.PublicKey, inner.RelatedOrigins))
	case "passkeys-get":
		if !h.knownKey(inner.Keys) {
			return h.reply(s, nonce, action, mustJSON(failMap("not associated")))
		}
		return h.reply(s, nonce, action, h.passkeysGet(inner.Origin, inner.PublicKey))
	default:
		body = failMap("unknown action")
	}
	return h.reply(s, nonce, action, mustJSON(body))
}

type assocKey struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

func (h *Host) hashBody() map[string]string {
	return map[string]string{
		"action":  "get-databasehash",
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
	if h.Origin != "" {
		return h.originLogins(rawURL)
	}
	if h.App == nil {
		return loginReply{Count: "0", Entries: []loginEntry{}, Success: "false", Hash: h.hash(), Version: Version}
	}
	human := protocol.Principal{Kind: protocol.PrincipalHuman, ID: h.App.HumanID, OrgID: h.App.OrgID}
	got, err := h.App.FillLogins(human, rawURL)
	if err != nil {
		return loginReply{Count: "0", Entries: []loginEntry{}, Success: "false", Hash: h.hash(), Version: Version}
	}
	entries := make([]loginEntry, 0, len(got))
	for _, e := range got {
		entries = append(entries, loginEntry{Login: e.Login, Name: e.Name, Password: e.Password, UUID: e.UUID})
	}
	return loginReply{
		Count:   strconv.Itoa(len(entries)),
		Entries: entries,
		Success: "true",
		Hash:    h.hash(),
		Version: Version,
	}
}

func (h *Host) originLogins(rawURL string) loginReply {
	empty := loginReply{Count: "0", Entries: []loginEntry{}, Success: "false", Hash: h.hash(), Version: Version}
	payload, err := json.Marshal(map[string]string{"url": rawURL})
	if err != nil {
		return empty
	}
	raw, err := h.originPOST("/v1/fill/logins", payload)
	if err != nil {
		return empty
	}
	var out struct {
		Entries []loginEntry `json:"entries"`
	}
	if json.Unmarshal(raw, &out) != nil {
		return empty
	}
	if out.Entries == nil {
		out.Entries = []loginEntry{}
	}
	return loginReply{
		Count:   strconv.Itoa(len(out.Entries)),
		Entries: out.Entries,
		Success: "true",
		Hash:    h.hash(),
		Version: Version,
	}
}

func (h *Host) totp(uuid string) map[string]string {
	if uuid == "" {
		return failMap("missing uuid")
	}
	if h.Origin != "" {
		return h.originTOTP(uuid)
	}
	if h.App == nil {
		return failMap("no totp")
	}
	human := protocol.Principal{Kind: protocol.PrincipalHuman, ID: h.App.HumanID, OrgID: h.App.OrgID}
	code, err := h.App.FillTOTP(human, uuid, time.Now())
	if err != nil || code == "" {
		return failMap("no totp")
	}
	return map[string]string{
		"totp":    code,
		"version": Version,
		"success": "true",
	}
}

func (h *Host) originTOTP(uuid string) map[string]string {
	payload, err := json.Marshal(map[string]string{"uuid": uuid})
	if err != nil {
		return failMap("no totp")
	}
	raw, err := h.originPOST("/v1/fill/totp", payload)
	if err != nil {
		return failMap("no totp")
	}
	var out struct {
		TOTP string `json:"totp"`
	}
	if json.Unmarshal(raw, &out) != nil || out.TOTP == "" {
		return failMap("no totp")
	}
	return map[string]string{
		"totp":    out.TOTP,
		"version": Version,
		"success": "true",
	}
}

type passkeyReply struct {
	Success  string          `json:"success"`
	Version  string          `json:"version"`
	Hash     string          `json:"hash"`
	Response json.RawMessage `json:"response"`
}

func (h *Host) passkeysRegister(origin string, publicKey json.RawMessage, extra []string) []byte {
	if h.Origin != "" {
		return h.originPasskeys("/v1/fill/passkeys/register", origin, publicKey, extra)
	}
	if h.App == nil {
		return h.passkeyErr(31)
	}
	human := protocol.Principal{Kind: protocol.PrincipalHuman, ID: h.App.HumanID, OrgID: h.App.OrgID}
	resp, err := h.App.FillPasskeyRegister(human, origin, publicKey, extra)
	if err != nil || len(resp) == 0 {
		return h.passkeyErr(31)
	}
	return h.passkeyOK(resp)
}

func (h *Host) passkeysGet(origin string, publicKey json.RawMessage) []byte {
	if h.Origin != "" {
		return h.originPasskeys("/v1/fill/passkeys/get", origin, publicKey, nil)
	}
	if h.App == nil {
		return h.passkeyErr(31)
	}
	human := protocol.Principal{Kind: protocol.PrincipalHuman, ID: h.App.HumanID, OrgID: h.App.OrgID}
	resp, err := h.App.FillPasskeyGet(human, origin, publicKey)
	if err != nil || len(resp) == 0 {
		return h.passkeyErr(31)
	}
	return h.passkeyOK(resp)
}

func (h *Host) originPasskeys(path, origin string, publicKey json.RawMessage, extra []string) []byte {
	payload, err := json.Marshal(struct {
		Origin         string          `json:"origin"`
		PublicKey      json.RawMessage `json:"publicKey"`
		RelatedOrigins []string        `json:"relatedOrigins,omitempty"`
	}{Origin: origin, PublicKey: publicKey, RelatedOrigins: extra})
	if err != nil {
		return h.passkeyErr(31)
	}
	raw, err := h.originPOST(path, payload)
	if err != nil {
		return h.passkeyErr(31)
	}
	var out struct {
		Response json.RawMessage `json:"response"`
	}
	if json.Unmarshal(raw, &out) != nil || len(out.Response) == 0 {
		return h.passkeyErr(31)
	}
	return h.passkeyOK(out.Response)
}

func (h *Host) passkeyOK(response json.RawMessage) []byte {
	raw, err := json.Marshal(passkeyReply{
		Success:  "true",
		Version:  Version,
		Hash:     h.hash(),
		Response: response,
	})
	if err != nil {
		return h.passkeyErr(31)
	}
	return raw
}

func (h *Host) passkeyErr(code int) []byte {
	resp, err := json.Marshal(map[string]int{"errorCode": code})
	if err != nil {
		resp = []byte(`{"errorCode":31}`)
	}
	return h.passkeyOK(resp)
}

func (h *Host) originPOST(path string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, h.Origin+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("fill origin: http %d", res.StatusCode)
	}
	return raw, nil
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
	sum := sha256.Sum256([]byte("pwm:" + h.orgID()))
	return hex.EncodeToString(sum[:])
}

func (h *Host) orgID() string {
	if h.App != nil && h.App.OrgID != "" {
		return h.App.OrgID
	}
	return "origin"
}

func (h *Host) dir() string {
	if h.App != nil && h.App.Dir != "" {
		return h.App.Dir
	}
	return h.Dir
}

func withNonce(plain []byte, nonce string) []byte {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(plain, &obj); err != nil {
		return plain
	}
	raw, err := json.Marshal(nonce)
	if err != nil {
		return plain
	}
	obj["nonce"] = raw
	out, err := json.Marshal(obj)
	if err != nil {
		return plain
	}
	return out
}

func (h *Host) reply(s *session, nonce [24]byte, action string, plain []byte) []byte {
	next := bumpNonce(nonce)
	nonceB64 := base64.StdEncoding.EncodeToString(next[:])
	boxed := box.Seal(nil, withNonce(plain, nonceB64), &next, &s.client, &s.priv)
	raw, err := json.Marshal(struct {
		Action  string `json:"action"`
		Message string `json:"message"`
		Nonce   string `json:"nonce"`
		Success string `json:"success"`
	}{
		Action:  action,
		Message: base64.StdEncoding.EncodeToString(boxed),
		Nonce:   nonceB64,
		Success: "true",
	})
	if err != nil {
		return fail(action, "marshal")
	}
	fillDebug("reply action=" + action + " nonce=" + nonceB64)
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
	if h.dir() == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(h.dir(), assocFile))
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
	if h.dir() == "" {
		return
	}
	raw, err := json.Marshal(assocDisk{ID: assocID, Key: key})
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(h.dir(), assocFile), raw, 0o600)
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
	return ShimOrigin(bin, home, "", "")
}

func ShimOrigin(bin, vaultHome, userHome, origin string) string {
	esc := func(s string) string { return strings.ReplaceAll(s, `"`, `\"`) }
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	if userHome != "" {
		b.WriteString("export HOME=\"" + esc(userHome) + "\"\n")
	}
	if origin != "" {
		b.WriteString("export PWM_ORIGIN=\"" + esc(origin) + "\"\n")
		token := "$HOME/.config/vortex/pwm-human.jwt"
		if userHome != "" {
			token = userHome + "/.config/vortex/pwm-human.jwt"
		}
		b.WriteString("export PWM_HUMAN_TOKEN_FILE=\"" + esc(token) + "\"\n")
	}
	b.WriteString("exec \"" + esc(bin) + "\" fill --home \"" + esc(vaultHome) + "\"\n")
	return b.String()
}
