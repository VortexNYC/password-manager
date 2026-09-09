// Package app is the product facade. CLI and MCP are thin wrappers around it.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vortexnyc/password-manager/internal/broker"
	"github.com/vortexnyc/password-manager/internal/crypto"
	"github.com/vortexnyc/password-manager/internal/id"
	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/store"
)

const (
	DefaultOrg   = "org"
	DefaultHuman = "self"
	dbFile       = "vault.db"
	keyFile      = "master.key"
	cfgFile      = "config.json"
)

var ErrExists = errors.New("app: vault already exists")

type config struct {
	OrgID   string `json:"org_id"`
	HumanID string `json:"human_id"`
}

type App struct {
	Dir     string
	OrgID   string
	HumanID string
	Store   store.Store
	Broker  *broker.Broker
}

func Init(dir string) (*App, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(dir, dbFile)); err == nil {
		return nil, ErrExists
	}
	key, err := crypto.NewKey()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, keyFile), key, 0o600); err != nil {
		return nil, err
	}
	cfg := config{OrgID: DefaultOrg, HumanID: DefaultHuman}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, cfgFile), raw, 0o600); err != nil {
		return nil, err
	}
	s, err := store.OpenSQLite(filepath.Join(dir, dbFile), key)
	if err != nil {
		return nil, err
	}
	if err := s.PutHuman(protocol.Principal{Kind: protocol.PrincipalHuman, ID: cfg.HumanID, OrgID: cfg.OrgID}); err != nil {
		_ = s.Close()
		return nil, err
	}
	return &App{
		Dir:     dir,
		OrgID:   cfg.OrgID,
		HumanID: cfg.HumanID,
		Store:   s,
		Broker:  broker.New(s),
	}, nil
}

func Open(dir string) (*App, error) {
	key, err := os.ReadFile(filepath.Join(dir, keyFile))
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, cfgFile))
	if err != nil {
		return nil, err
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	s, err := store.OpenSQLite(filepath.Join(dir, dbFile), key)
	if err != nil {
		return nil, err
	}
	return &App{
		Dir:     dir,
		OrgID:   cfg.OrgID,
		HumanID: cfg.HumanID,
		Store:   s,
		Broker:  broker.New(s),
	}, nil
}

func (a *App) Close() error {
	if a.Store != nil {
		return a.Store.Close()
	}
	return nil
}

func (a *App) AddItem(name, uri string, secret []byte) (protocol.Item, error) {
	if !id.Valid(name) {
		return protocol.Item{}, fmt.Errorf("app: invalid item name %q", name)
	}
	if len(secret) == 0 {
		return protocol.Item{}, fmt.Errorf("app: empty secret")
	}
	item := protocol.Item{
		ID:    name,
		OrgID: a.OrgID,
		Name:  name,
		Kind:  protocol.ItemAPIKey,
		Owner: protocol.Owner{Kind: protocol.OwnerOrg, ID: a.OrgID},
	}
	if uri != "" {
		item.URIs = []string{uri}
	}
	if err := a.Store.PutItem(item, store.Secret(secret)); err != nil {
		return protocol.Item{}, err
	}
	return item, nil
}

func (a *App) AddAgent(name string) (protocol.Principal, error) {
	if !id.Valid(name) {
		return protocol.Principal{}, fmt.Errorf("app: invalid agent name %q", name)
	}
	p := protocol.Principal{Kind: protocol.PrincipalAgent, ID: name, OrgID: a.OrgID}
	if err := a.Store.PutAgent(p); err != nil {
		return protocol.Principal{}, err
	}
	return p, nil
}

func (a *App) AddGrant(agentID, itemID string, level protocol.GrantLevel) (protocol.Grant, error) {
	if !id.Valid(agentID) || !id.Valid(itemID) {
		return protocol.Grant{}, fmt.Errorf("app: invalid agent or item")
	}
	if level != protocol.Level1 && level != protocol.Level2 {
		return protocol.Grant{}, fmt.Errorf("app: level must be level1 or level2")
	}
	if _, err := a.Store.Agent(agentID); err != nil {
		return protocol.Grant{}, err
	}
	if _, err := a.Store.Item(itemID); err != nil {
		return protocol.Grant{}, err
	}
	g := protocol.Grant{
		ID:      id.Grant(agentID, itemID),
		OrgID:   a.OrgID,
		AgentID: agentID,
		ItemID:  itemID,
		Level:   level,
		Actions: []protocol.ActionKind{protocol.ActionFetch},
	}
	if err := a.Store.PutGrant(g); err != nil {
		return protocol.Grant{}, err
	}
	return g, nil
}

func (a *App) Use(ctx context.Context, agentID, itemID, method, rawURL string) (protocol.UseResult, error) {
	agent, err := a.Store.Agent(agentID)
	if err != nil {
		return protocol.UseResult{}, err
	}
	return a.Broker.Use(ctx, agent, protocol.UseRequest{
		ItemID: itemID,
		Action: protocol.ActionFetch,
		Fetch:  &protocol.Fetch{Method: method, URL: rawURL},
	})
}

func (a *App) Approve(grantID string, ttl time.Duration) (protocol.Approval, error) {
	human, err := a.Store.Human(a.HumanID)
	if err != nil {
		return protocol.Approval{}, err
	}
	if _, err := a.Store.Grant(grantID); err != nil {
		return protocol.Approval{}, err
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return a.Broker.Approve(human, grantID, ttl)
}

func (a *App) ItemsForAgent(agentID string) ([]protocol.Item, error) {
	grants, err := a.Store.ListGrants()
	if err != nil {
		return nil, err
	}
	var out []protocol.Item
	for _, g := range grants {
		if g.AgentID != agentID {
			continue
		}
		item, err := a.Store.Item(g.ItemID)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}
