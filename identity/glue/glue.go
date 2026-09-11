// Package glue is the seam. It wires Kratos, Hydra, and Keto.
//
// Official Ory Go clients live in the matching directory — not here:
//
//	glue/kratos  kratos-client-go     humans
//	glue/hydra   hydra-client-go     tokens
//	glue/keto    keto-client-go      owner / member
//
// Login is Kratos oauth2_provider, not this package.
// To leave Ory, replace those three directories. This package stays the wiring.
package glue

import (
	"context"
	"fmt"
	"net/http"

	"github.com/vortexnyc/password-manager/identity/glue/hydra"
	"github.com/vortexnyc/password-manager/identity/glue/keto"
	"github.com/vortexnyc/password-manager/identity/glue/kratos"
	"github.com/vortexnyc/password-manager/internal/protocol"
)

const (
	LocalOrgID        = protocol.LocalOrgID
	DefaultClientID   = hydra.DefaultClientID
	AgentClientPrefix = hydra.AgentClientPrefix
	relOwners         = keto.RelOwners
	relMembers        = keto.RelMembers
)

type (
	Invite      = kratos.Invite
	AgentClient = hydra.AgentClient
	AgentCred   = hydra.AgentCred
	FirstParty  = hydra.FirstParty
)

type Config struct {
	KratosPublic string
	KratosAdmin  string
	HydraAdmin   string
	KetoRead     string
	KetoWrite    string
	OrgID        string
}

type Glue struct {
	humans  *kratos.Client
	tokens  *hydra.Client
	members *keto.Client
}

func New(cfg Config) (*Glue, error) {
	humans, err := kratos.New(cfg.KratosPublic, cfg.KratosAdmin)
	if err != nil {
		return nil, fmt.Errorf("glue: %w", err)
	}
	tokens, err := hydra.New(cfg.HydraAdmin)
	if err != nil {
		return nil, fmt.Errorf("glue: %w", err)
	}
	members, err := keto.New(cfg.KetoRead, cfg.KetoWrite, cfg.OrgID)
	if err != nil {
		return nil, fmt.Errorf("glue: %w", err)
	}
	return &Glue{
		humans:  humans,
		tokens:  tokens,
		members: members,
	}, nil
}

func NewHydra(admin string) (*Glue, error) {
	tokens, err := hydra.New(admin)
	if err != nil {
		return nil, fmt.Errorf("glue: %w", err)
	}
	return &Glue{tokens: tokens}, nil
}

func (g *Glue) org() string {
	if g.members != nil {
		return g.members.Org()
	}
	return LocalOrgID
}

func (g *Glue) EnsureFirstParty(ctx context.Context, fp FirstParty) error {
	if g.tokens == nil {
		return fmt.Errorf("glue: hydra admin not configured")
	}
	return g.tokens.EnsureFirstParty(ctx, fp)
}

func (g *Glue) AcceptConsent(ctx context.Context, challenge string) (string, error) {
	if g.tokens == nil {
		return "", fmt.Errorf("glue: hydra admin not configured")
	}
	return g.tokens.AcceptConsent(ctx, challenge)
}

func (g *Glue) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	consent := r.URL.Query().Get("consent_challenge")
	if consent == "" {
		http.Error(w, "missing consent_challenge", http.StatusBadRequest)
		return
	}
	redirectTo, err := g.AcceptConsent(r.Context(), consent)
	if err != nil {
		http.Error(w, "consent request failed", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func (g *Glue) EnsureAgent(ctx context.Context, ac AgentClient) (AgentCred, error) {
	if g.tokens == nil {
		return AgentCred{}, fmt.Errorf("glue: hydra admin not configured")
	}
	return g.tokens.EnsureAgent(ctx, ac)
}

func ClientCredentials(ctx context.Context, issuer, clientID, secret, audience string) (string, error) {
	return hydra.ClientCredentials(ctx, issuer, clientID, secret, audience)
}

func AgentClientID(agentID string) string {
	return hydra.AgentClientID(agentID)
}

func (g *Glue) Allowed(ctx context.Context, relation, subject string) (bool, error) {
	if g.members == nil {
		return false, fmt.Errorf("glue: keto is required")
	}
	return g.members.Allowed(ctx, relation, subject)
}

func (g *Glue) IsMember(ctx context.Context, identityID string) (bool, error) {
	if g.members == nil {
		return false, fmt.Errorf("glue: keto is required")
	}
	return g.members.IsMember(ctx, identityID)
}

func (g *Glue) IsOwner(ctx context.Context, identityID string) (bool, error) {
	if g.members == nil {
		return false, fmt.Errorf("glue: keto is required")
	}
	return g.members.IsOwner(ctx, identityID)
}

// IdentityID is the Kratos id for an email. CLI grant --human. Broker never
// calls this. Email stays in Kratos.
func (g *Glue) IdentityID(ctx context.Context, email string) (string, error) {
	if g.humans == nil {
		return "", fmt.Errorf("glue: kratos admin is required")
	}
	return g.humans.IdentityByEmail(ctx, email, g.org())
}

func (g *Glue) addOrgMember(ctx context.Context, identityID string) error {
	if g.members == nil {
		return nil
	}
	return g.members.AddMember(ctx, identityID)
}

func (g *Glue) IdentityOrg(ctx context.Context, identityID string) (string, error) {
	if g.humans == nil {
		return "", fmt.Errorf("glue: kratos admin is required")
	}
	return g.humans.Organization(ctx, identityID)
}
