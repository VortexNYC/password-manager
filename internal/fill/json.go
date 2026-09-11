package fill

import (
	"encoding/json"
	"strings"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/grant"
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
		Action string `json:"action"`
		URL    string `json:"url"`
		App    string `json:"app"`
		UUID   string `json:"uuid"`
	}
	if json.Unmarshal(raw, &in) != nil {
		return jsonFillReply(nil, "")
	}
	switch in.Action {
	case "ping":
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

func jsonBytes(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"entries":[]}`)
	}
	return raw
}
