// Package app is the product facade. CLI and MCP are thin wrappers around it.
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vortexnyc/password-manager/internal/broker"
	"github.com/vortexnyc/password-manager/internal/crypto"
	"github.com/vortexnyc/password-manager/internal/device"
	"github.com/vortexnyc/password-manager/internal/human"
	"github.com/vortexnyc/password-manager/internal/id"
	"github.com/vortexnyc/password-manager/internal/inject"
	"github.com/vortexnyc/password-manager/internal/material"
	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/store"
	"github.com/vortexnyc/password-manager/internal/workload"
)

const (
	DefaultOrg   = protocol.LocalOrgID
	DefaultHuman = "self"
	dbFile       = "vault.db"
	cfgFile      = "config.json"
)

// MemberCheck is identity-plane membership. Keto via glue. Not grants.
type MemberCheck interface {
	IsMember(ctx context.Context, identityID string) (bool, error)
}

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
	Human   *human.Verifier
	Members MemberCheck
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
	_, priv, err := device.Generate()
	if err != nil {
		return nil, err
	}
	if err := wrapMaster(dir, key, priv); err != nil {
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
	return finish(dir, cfg, s)
}

func Open(dir string) (*App, error) {
	key, err := loadMaster(dir)
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
	return finish(dir, cfg, s)
}

func finish(dir string, cfg config, s store.Store) (*App, error) {
	a := &App{
		Dir:     dir,
		OrgID:   cfg.OrgID,
		HumanID: cfg.HumanID,
		Store:   s,
		Broker:  broker.New(s),
	}
	if err := a.attachHydra(); err != nil {
		_ = s.Close()
		return nil, err
	}
	return a, nil
}

func (a *App) attachHydra() error {
	iss := os.Getenv("PWM_HYDRA_ISSUER")
	if iss == "" {
		return nil
	}
	v, err := human.New(human.Config{
		Issuer:      iss,
		Audience:    os.Getenv("PWM_HYDRA_CLIENT_ID"),
		RedirectURL: firstEnv("PWM_HYDRA_REDIRECT", "BROKER_REDIRECT_URL"),
	})
	if err != nil {
		return err
	}
	a.Human = v
	return nil
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func (a *App) Close() error {
	if a.Store != nil {
		return a.Store.Close()
	}
	return nil
}

type ItemOpts struct {
	Name         string
	URI          string
	URIs         []string
	Tags         []string
	Kind         protocol.ItemKind
	Token        []byte
	TOTPSeed     []byte
	Refresh      []byte
	TokenURL     string
	ClientID     string
	ClientSecret []byte
	FileName     string
	MIME         string
	File         []byte
}

func (a *App) AddItem(name, uri string, secret []byte) (protocol.Item, error) {
	return a.PutItem(ItemOpts{Name: name, URI: uri, Token: secret})
}

func (a *App) PutItem(opts ItemOpts) (protocol.Item, error) {
	if !id.Valid(opts.Name) {
		return protocol.Item{}, fmt.Errorf("app: invalid item name %q", opts.Name)
	}
	if len(opts.Token) == 0 && len(opts.TOTPSeed) == 0 && len(opts.Refresh) == 0 && len(opts.File) == 0 {
		return protocol.Item{}, fmt.Errorf("app: empty secret")
	}
	kind := opts.Kind
	if kind == "" {
		switch {
		case len(opts.File) > 0:
			kind = protocol.ItemFile
		case len(opts.Refresh) > 0:
			kind = protocol.ItemOAuth
		default:
			kind = protocol.ItemAPIKey
		}
	}
	uris := opts.URIs
	if opts.URI != "" {
		uris = append([]string{opts.URI}, uris...)
	}
	item := protocol.Item{
		ID:      opts.Name,
		OrgID:   a.OrgID,
		Name:    opts.Name,
		Kind:    kind,
		Owner:   protocol.Owner{Kind: protocol.OwnerOrg, ID: a.OrgID},
		URIs:    uris,
		Tags:    opts.Tags,
		HasTOTP: len(opts.TOTPSeed) > 0,
		HasFile: len(opts.File) > 0,
	}
	var blob []byte
	var err error
	switch {
	case len(opts.File) > 0:
		blob, err = material.PackFile(opts.FileName, opts.MIME, opts.File)
	case len(opts.Refresh) > 0:
		blob, err = material.PackOAuth(opts.Refresh, []byte(opts.TokenURL), []byte(opts.ClientID), opts.ClientSecret)
	case len(opts.TOTPSeed) > 0:
		blob, err = material.Pack(opts.Token, opts.TOTPSeed)
	default:
		blob = opts.Token
	}
	if err != nil {
		return protocol.Item{}, err
	}
	if err := a.Store.PutItem(item, store.Secret(blob)); err != nil {
		return protocol.Item{}, err
	}
	return item, nil
}

func (a *App) UpdateItem(name string, uris, tags []string) (protocol.Item, error) {
	item, err := a.Store.Item(name)
	if err != nil {
		return protocol.Item{}, err
	}
	secret, err := a.Store.Secret(item.ID)
	if err != nil {
		return protocol.Item{}, err
	}
	if uris != nil {
		item.URIs = uris
	}
	if tags != nil {
		item.Tags = tags
	}
	if err := a.Store.PutItem(item, secret); err != nil {
		return protocol.Item{}, err
	}
	return item, nil
}

func (a *App) ArchiveItem(name string) error {
	return a.Store.ArchiveItem(name)
}

func (a *App) DeleteItem(name string) error {
	return a.Store.DeleteItem(name)
}

func (a *App) WriteFile(name, dest string) error {
	item, err := a.Store.Item(name)
	if err != nil {
		return err
	}
	if !item.HasFile && item.Kind != protocol.ItemFile {
		return fmt.Errorf("app: not a file")
	}
	raw, err := a.Store.Secret(item.ID)
	if err != nil {
		return err
	}
	body, err := material.FileBytes(material.Unpack(secretBytes(raw)))
	if err != nil {
		return err
	}
	return os.WriteFile(dest, body, 0o600)
}

func secretBytes(s store.Secret) []byte { return []byte(s) }

func (a *App) AddAgent(name string) (protocol.Principal, error) {
	if !id.Valid(name) {
		return protocol.Principal{}, fmt.Errorf("app: invalid agent name %q", name)
	}
	p := protocol.Principal{
		Kind:  protocol.PrincipalAgent,
		ID:    name,
		OrgID: a.OrgID,
		Owner: protocol.Owner{Kind: protocol.OwnerUser, ID: a.HumanID},
	}
	if err := a.Store.PutAgent(p); err != nil {
		return protocol.Principal{}, err
	}
	return p, nil
}

func (a *App) BindWorkload(agentID, issuer, subject, audience string) (protocol.Workload, error) {
	if !id.Valid(agentID) {
		return protocol.Workload{}, fmt.Errorf("app: invalid agent name %q", agentID)
	}
	if issuer == "" || subject == "" || audience == "" {
		return protocol.Workload{}, fmt.Errorf("app: issuer, subject, and audience are required")
	}
	if _, err := a.Store.Agent(agentID); err != nil {
		return protocol.Workload{}, err
	}
	w := protocol.Workload{
		AgentID:  agentID,
		Issuer:   issuer,
		Subject:  subject,
		Audience: audience,
	}
	if err := a.Store.PutWorkload(w); err != nil {
		return protocol.Workload{}, err
	}
	return w, nil
}

func (a *App) AgentFromOIDC(ctx context.Context, rawToken string) (protocol.Principal, error) {
	return workload.New(a.Store).Agent(ctx, rawToken)
}

func (a *App) AddGrant(agentID, itemID string, level protocol.GrantLevel) (protocol.Grant, error) {
	return a.GrantUntil(agentID, itemID, level, nil)
}

func (a *App) GrantUntil(agentID, itemID string, level protocol.GrantLevel, expires *time.Time) (protocol.Grant, error) {
	if !id.Valid(agentID) || !id.Valid(itemID) {
		return protocol.Grant{}, fmt.Errorf("app: invalid agent or item")
	}
	if level != protocol.Level1 && level != protocol.Level2 {
		return protocol.Grant{}, fmt.Errorf("app: level must be level1 or level2")
	}
	agent, err := a.Store.Agent(agentID)
	if err != nil {
		return protocol.Grant{}, err
	}
	if agent.Owner.ID != "" && agent.Owner.ID != a.HumanID {
		return protocol.Grant{}, fmt.Errorf("app: not the owner")
	}
	item, err := a.Store.Item(itemID)
	if err != nil {
		return protocol.Grant{}, err
	}
	if item.Archived {
		return protocol.Grant{}, fmt.Errorf("app: item archived")
	}
	g := protocol.Grant{
		ID:        id.Grant(agentID, itemID),
		OrgID:     a.OrgID,
		AgentID:   agentID,
		ItemID:    itemID,
		Level:     level,
		Actions:   []protocol.ActionKind{protocol.ActionFetch},
		ExpiresAt: expires,
	}
	if err := a.Store.PutGrant(g); err != nil {
		return protocol.Grant{}, err
	}
	return g, nil
}

func (a *App) Use(ctx context.Context, agentID, itemID, method, rawURL string) (protocol.UseResult, error) {
	return a.UseFetch(ctx, agentID, itemID, protocol.Fetch{Method: method, URL: rawURL})
}

func (a *App) UseFetch(ctx context.Context, agentID, itemID string, fetch protocol.Fetch) (protocol.UseResult, error) {
	agent, err := a.Store.Agent(agentID)
	if err != nil {
		return protocol.UseResult{}, err
	}
	return a.Broker.Use(ctx, agent, protocol.UseRequest{
		ItemID: itemID,
		Action: protocol.ActionFetch,
		Fetch:  &fetch,
	})
}

func (a *App) ChildEnv(ctx context.Context, agentID string) ([]string, error) {
	agent, err := a.Store.Agent(agentID)
	if err != nil {
		return nil, err
	}
	return a.Broker.ChildEnv(ctx, agent)
}

func (a *App) InjectFile(src, dest string, pairs []string) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	out, err := inject.Expand(raw, inject.Map(pairs))
	if err != nil {
		return err
	}
	return os.WriteFile(dest, out, 0o600)
}

func (a *App) Approve(grantID string, ttl time.Duration) (protocol.Approval, error) {
	if a.Human != nil {
		return protocol.Approval{}, fmt.Errorf("app: use ApproveOIDC")
	}
	humanP, err := a.Store.Human(a.HumanID)
	if err != nil {
		return protocol.Approval{}, err
	}
	if _, err := a.Store.Grant(grantID); err != nil {
		return protocol.Approval{}, err
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return a.Broker.Approve(humanP, grantID, ttl)
}

// ApproveOIDC is Approve with a Hydra ID token. Membership is Keto, not sqlite.
// Planted `self` is the laptop stand-in when no issuer is configured.
func (a *App) ApproveOIDC(ctx context.Context, grantID, rawToken string, ttl time.Duration) (protocol.Approval, error) {
	if a.Human == nil {
		return protocol.Approval{}, fmt.Errorf("app: hydra issuer not configured")
	}
	if a.Members == nil {
		return protocol.Approval{}, fmt.Errorf("app: not a member")
	}
	p, err := a.Human.Human(ctx, rawToken, a.OrgID)
	if err != nil {
		return protocol.Approval{}, err
	}
	ok, err := a.Members.IsMember(ctx, p.ID)
	if err != nil {
		return protocol.Approval{}, err
	}
	if !ok {
		return protocol.Approval{}, fmt.Errorf("app: not a member")
	}
	if _, err := a.Store.Grant(grantID); err != nil {
		return protocol.Approval{}, err
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return a.Broker.Approve(p, grantID, ttl)
}

// Offer wraps master to a second device's public key. nacl box.
// The blob is not JSON. The grant does not get a copy. Master is not a file.
func (a *App) Offer(peerPub []byte) ([]byte, error) {
	master, err := loadMaster(a.Dir)
	if err != nil {
		return nil, err
	}
	blob, err := device.Offer(master, peerPub)
	if err != nil {
		return nil, err
	}
	if err := persistWrap(a.Dir, peerPub, blob); err != nil {
		return nil, err
	}
	return blob, nil
}

// Accept writes device.key and a wrap. Not a second vault. Not plaintext master.
// Copy vault.db and config.json yourself. This is not sync.
func Accept(dir string, priv, blob []byte) error {
	master, err := device.Accept(blob, priv)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, deviceFile)
	existing, err := os.ReadFile(path)
	if err == nil && !bytes.Equal(existing, priv) {
		return fmt.Errorf("app: device.key exists")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	pub, err := device.Public(priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return err
	}
	if err := persistWrap(dir, pub, blob); err != nil {
		return err
	}
	legacy := filepath.Join(dir, keyFile)
	if got, err := os.ReadFile(legacy); err == nil {
		if !bytes.Equal(got, master) {
			return fmt.Errorf("app: master.key exists")
		}
		if err := os.Remove(legacy); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
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
		if item.Archived {
			continue
		}
		out = append(out, item)
	}
	return out, nil
}
