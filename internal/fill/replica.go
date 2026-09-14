package fill

import (
	"encoding/json"
	"time"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/material"
	"github.com/vortexnyc/password-manager/internal/publicapi"
)

func (h *Host) replicaWarm() bool {
	return h.Replica != nil && h.Replica.Len() > 0
}

func (h *Host) PullReplica() error {
	if h.Replica == nil || h.Origin == "" {
		return nil
	}
	raw, err := h.originPOST("/v1/fill/sync", []byte("{}"))
	if err != nil {
		return err
	}
	var out publicapi.FillSyncResponse
	if json.Unmarshal(raw, &out) != nil {
		return errGenerateCreate
	}
	for _, row := range out.Items {
		if err := h.Replica.Put(row.Item, []byte(row.Material)); err != nil {
			return err
		}
	}
	h.invalidateIndex()
	return nil
}

func (h *Host) replicaFill(uuid string, mintTotp bool) (app.FillEntry, bool) {
	raw := h.Replica.Material(uuid)
	if raw == "" {
		return app.FillEntry{}, false
	}
	env := material.Unpack([]byte(raw))
	if env.PasskeyPEM != "" {
		return app.FillEntry{}, false
	}
	itemName := uuid
	for _, it := range h.Replica.Items() {
		if it.ID == uuid {
			itemName = it.Name
			if env.Login == "" {
				env.Login = it.Login
			}
			break
		}
	}
	pass := env.Token
	if pass == "" {
		pass = raw
	}
	totp := ""
	if env.TOTP != "" {
		totp = totpPresent
		if mintTotp {
			code, err := material.Mint(env.TOTP, time.Now())
			if err != nil || code == "" {
				return app.FillEntry{}, false
			}
			totp = code
		}
	}
	return app.FillEntry{Login: env.Login, Name: itemName, Password: pass, UUID: uuid, TOTP: totp}, true
}
