package fill

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/grant"
	"github.com/vortexnyc/password-manager/internal/passgen"
	"github.com/vortexnyc/password-manager/internal/protocol"
)

type jsonMatchEntry struct {
	UUID       string `json:"uuid"`
	Name       string `json:"name"`
	Login      string `json:"login,omitempty"`
	Kind       string `json:"kind"`
	HasTOTP    bool   `json:"hasTotp,omitempty"`
	HasPasskey bool   `json:"hasPasskey,omitempty"`
	SavedFor   string `json:"savedFor,omitempty"`
	Affiliated bool   `json:"affiliated,omitempty"`
}

type jsonFillEntry struct {
	Kind     string `json:"kind"`
	Login    string `json:"login"`
	Password string `json:"password"`
	TOTP     string `json:"totp,omitempty"`
	UUID     string `json:"uuid"`
	Name     string `json:"name"`
}

func (h *Host) handleJSON(raw []byte) []byte {
	var in struct {
		Action         string          `json:"action"`
		URL            string          `json:"url"`
		App            string          `json:"app"`
		UUID           string          `json:"uuid"`
		Login          string          `json:"login"`
		PasswordRules  string          `json:"passwordRules"`
		Origin         string          `json:"origin"`
		PublicKey      json.RawMessage `json:"publicKey"`
		RelatedOrigins []string        `json:"relatedOrigins"`
	}
	if json.Unmarshal(raw, &in) != nil {
		return jsonFillReply(nil, "")
	}
	switch in.Action {
	case "ping":
		if h.Replica != nil {
			_ = h.PullReplica()
		}
		h.ensureIndex()
		out := struct {
			Version string `json:"version"`
			Error   string `json:"error,omitempty"`
		}{Version: JSONVersion}
		if h.loginNeeded() {
			out.Error = "need_login"
		}
		return jsonBytes(out)
	case "match":
		return jsonBytes(struct {
			Entries []jsonMatchEntry `json:"entries"`
		}{Entries: h.jsonMatch(in.URL)})
	case "fill":
		entries := h.jsonFill(in.URL, in.UUID)
		err := ""
		if len(entries) == 0 && h.loginNeeded() {
			err = "need_login"
		}
		return jsonFillReply(entries, err)
	case "generate":
		return h.jsonGenerate(in.URL, in.Login, in.PasswordRules)
	case "passkeyCreate":
		return h.jsonPasskeyCreate(in.Origin, in.PublicKey, in.RelatedOrigins)
	case "passkeyGet":
		return h.jsonPasskeyGet(in.Origin, in.PublicKey)
	default:
		return jsonFillReply(nil, "")
	}
}

func jsonFillReply(entries []jsonFillEntry, err string) []byte {
	if entries == nil {
		entries = []jsonFillEntry{}
	}
	return jsonBytes(struct {
		Entries []jsonFillEntry `json:"entries"`
		Error   string          `json:"error,omitempty"`
	}{Entries: entries, Error: err})
}

func (h *Host) jsonMatch(rawURL string) []jsonMatchEntry {
	out := []jsonMatchEntry{}
	if strings.TrimSpace(rawURL) == "" {
		return out
	}
	h.ensureIndex()
	h.mu.Lock()
	items := append([]protocol.Item(nil), h.index...)
	h.mu.Unlock()
	for _, item := range items {
		if item.Archived {
			continue
		}
		if item.Kind == protocol.ItemSSH || item.Kind == protocol.ItemFile {
			continue
		}
		if !grant.HostAllowed(item, rawURL) {
			continue
		}
		out = append(out, matchEntry(item))
	}
	return out
}

func (h *Host) jsonFill(rawURL, uuid string) []jsonFillEntry {
	empty := []jsonFillEntry{}
	matches := h.jsonMatch(rawURL)
	uuid = strings.TrimSpace(uuid)
	var hit *jsonMatchEntry
	if uuid == "" {
		if len(matches) != 1 {
			return empty
		}
		hit = &matches[0]
	} else {
		for i := range matches {
			if matches[i].UUID == uuid {
				hit = &matches[i]
				break
			}
		}
		if hit == nil {
			return empty
		}
	}
	if hit.Kind != "login" || hit.Affiliated {
		return empty
	}
	if err := h.confirm("Veil wants to fill a saved sign-in"); err != nil {
		return empty
	}
	got, ok := h.unlockJSONFill(hit.UUID, hit.HasTOTP)
	if !ok {
		return empty
	}
	if got.TOTP == totpPresent || len(got.TOTP) > 8 {
		got.TOTP = ""
	}
	return []jsonFillEntry{{
		Kind:     "login",
		Login:    got.Login,
		Password: got.Password,
		TOTP:     got.TOTP,
		UUID:     got.UUID,
		Name:     got.Name,
	}}
}

func (h *Host) unlockJSONFill(uuid string, mintTotp bool) (app.FillEntry, bool) {
	if h.replicaWarm() {
		if got, ok := h.replicaFill(uuid, mintTotp); ok {
			return got, true
		}
	}
	if h.Origin != "" {
		payload, err := json.Marshal(struct {
			UUID     string `json:"uuid"`
			MintTOTP bool   `json:"mintTotp,omitempty"`
		}{UUID: uuid, MintTOTP: mintTotp})
		if err != nil {
			return app.FillEntry{}, false
		}
		raw, err := h.originPOST("/v1/fill/logins", payload)
		if err != nil {
			return app.FillEntry{}, false
		}
		var out struct {
			Entries []app.FillEntry `json:"entries"`
		}
		if json.Unmarshal(raw, &out) != nil || len(out.Entries) != 1 {
			return app.FillEntry{}, false
		}
		return out.Entries[0], true
	}
	if h.App == nil {
		return app.FillEntry{}, false
	}
	human := protocol.Principal{Kind: protocol.PrincipalHuman, ID: h.App.HumanID, OrgID: h.App.OrgID}
	got, err := h.App.FillLogin(human, uuid, mintTotp)
	if err != nil {
		return app.FillEntry{}, false
	}
	return got, true
}

func (h *Host) ensureIndex() {
	h.mu.Lock()
	ok := h.indexOK
	h.mu.Unlock()
	if ok {
		return
	}
	h.reloadIndex()
}

func (h *Host) invalidateIndex() {
	h.mu.Lock()
	h.index = nil
	h.indexOK = false
	h.mu.Unlock()
}

func (h *Host) reloadIndex() {
	var items []protocol.Item
	switch {
	case h.replicaWarm():
		items = h.Replica.Items()
	case h.Origin != "":
		raw, err := h.originGET("/v1/items")
		if err != nil {
			return
		}
		var out struct {
			Items []protocol.Item `json:"items"`
		}
		if json.Unmarshal(raw, &out) != nil {
			return
		}
		items = out.Items
	case h.App != nil:
		human := protocol.Principal{Kind: protocol.PrincipalHuman, ID: h.App.HumanID, OrgID: h.App.OrgID}
		got, err := h.App.ItemsForPrincipal(human)
		if err != nil {
			return
		}
		items = got
	default:
		return
	}
	if items == nil {
		items = []protocol.Item{}
	}
	h.mu.Lock()
	h.index = items
	h.indexOK = true
	h.mu.Unlock()
}

func matchEntry(item protocol.Item) jsonMatchEntry {
	kind := "login"
	hasPasskey := item.Kind == protocol.ItemPasskey
	if hasPasskey {
		kind = "passkey"
	}
	saved := ""
	if len(item.URIs) > 0 {
		if u, err := grant.ParseDest(item.URIs[0]); err == nil {
			saved = grant.CanonicalHost(u)
		}
	}
	return jsonMatchEntry{
		UUID:       item.ID,
		Name:       item.Name,
		Login:      item.Login,
		Kind:       kind,
		HasTOTP:    item.HasTOTP,
		HasPasskey: hasPasskey,
		SavedFor:   saved,
	}
}

func (h *Host) jsonGenerate(rawURL, login, rules string) []byte {
	rawURL = strings.TrimSpace(rawURL)
	login = strings.TrimSpace(login)
	if rawURL == "" {
		return jsonGenerateErr("failed")
	}
	uri, host, ok := generateURI(rawURL)
	if !ok {
		return jsonGenerateErr("failed")
	}
	matches := h.jsonMatch(rawURL)
	if h.loginNeeded() {
		return jsonGenerateErr("need_login")
	}
	for _, e := range matches {
		if e.Kind == "login" {
			return jsonGenerateErr("choose")
		}
	}
	if err := h.confirm("Veil wants to save a new password"); err != nil {
		return jsonGenerateErr("canceled")
	}
	secret, err := passgen.FromRules(rules)
	if err != nil {
		return jsonGenerateErr("failed")
	}
	name := host
	item, err := h.createGeneratedLogin(name, uri, login, string(secret))
	if err != nil {
		if h.loginNeeded() {
			return jsonGenerateErr("need_login")
		}
		return jsonGenerateErr("failed")
	}
	h.invalidateIndex()
	return jsonBytes(struct {
		UUID     string `json:"uuid"`
		Name     string `json:"name"`
		Login    string `json:"login,omitempty"`
		Password string `json:"password"`
	}{UUID: item.ID, Name: item.Name, Login: login, Password: string(secret)})
}

func (h *Host) createGeneratedLogin(name, uri, login, secret string) (protocol.Item, error) {
	if h.Origin != "" {
		payload, err := json.Marshal(struct {
			Name   string `json:"name"`
			URI    string `json:"uri"`
			Secret string `json:"secret"`
			Login  string `json:"login,omitempty"`
		}{Name: name, URI: uri, Secret: secret, Login: login})
		if err != nil {
			return protocol.Item{}, err
		}
		raw, err := h.originPOST("/v1/items", payload)
		if err != nil {
			return protocol.Item{}, err
		}
		var item protocol.Item
		if json.Unmarshal(raw, &item) != nil || item.ID == "" {
			return protocol.Item{}, errGenerateCreate
		}
		return item, nil
	}
	if h.App == nil {
		return protocol.Item{}, errGenerateCreate
	}
	return h.App.PutItem(app.ItemOpts{Name: name, URI: uri, Token: []byte(secret), Login: login})
}

func generateURI(rawURL string) (uri, host string, ok bool) {
	u, err := grant.ParseDest(rawURL)
	if err != nil {
		return "", "", false
	}
	host = grant.CanonicalHost(u)
	if host == "" {
		return "", "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		scheme = "https"
	}
	return scheme + "://" + host, host, true
}

func jsonGenerateErr(err string) []byte {
	return jsonBytes(struct {
		Error string `json:"error"`
	}{Error: err})
}

var errGenerateCreate = errors.New("generate create failed")

func (h *Host) jsonPasskeyCreate(origin string, publicKey json.RawMessage, extra []string) []byte {
	origin = strings.TrimSpace(origin)
	if origin == "" || len(publicKey) == 0 {
		return jsonPasskeyErr("failed")
	}
	if err := h.confirm("Veil wants to save a passkey"); err != nil {
		return jsonPasskeyErr("canceled")
	}
	return jsonPasskeyFromHost(h.passkeysRegister(origin, publicKey, extra))
}

func (h *Host) jsonPasskeyGet(origin string, publicKey json.RawMessage) []byte {
	origin = strings.TrimSpace(origin)
	if origin == "" || len(publicKey) == 0 {
		return jsonPasskeyErr("failed")
	}
	if err := h.confirm("Veil wants to use a passkey"); err != nil {
		return jsonPasskeyErr("canceled")
	}
	return jsonPasskeyFromHost(h.passkeysGet(origin, publicKey))
}

func jsonPasskeyFromHost(raw []byte) []byte {
	var r passkeyReply
	if json.Unmarshal(raw, &r) != nil || r.Success != "true" || len(r.Response) == 0 {
		return jsonPasskeyErr("failed")
	}
	var inner struct {
		ErrorCode int `json:"errorCode"`
	}
	if json.Unmarshal(r.Response, &inner) == nil && inner.ErrorCode != 0 {
		return jsonPasskeyErr("failed")
	}
	return jsonBytes(struct {
		Response json.RawMessage `json:"response"`
	}{Response: r.Response})
}

func jsonPasskeyErr(err string) []byte {
	return jsonBytes(struct {
		Error string `json:"error"`
	}{Error: err})
}

func jsonBytes(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"entries":[]}`)
	}
	return raw
}
