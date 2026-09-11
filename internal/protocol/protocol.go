// Package protocol is the one API every surface speaks: CLI, MCP, SDK, proxy.
//
// Agents never receive a Secret. They Resolve metadata, Use an action, and
// wait on Approve for level-1 grants. Injection happens inside the broker.
package protocol

import (
	"net/http"
	"time"
)

type PrincipalKind string

const (
	PrincipalHuman PrincipalKind = "human"
	PrincipalAgent PrincipalKind = "agent"
)

type OwnerKind string

const (
	OwnerUser OwnerKind = "user"
	OwnerOrg  OwnerKind = "org"
)

// LocalOrgID is the one Vortex organization. Same value in the vault,
// Kratos organization_id, and the Keto object. A second company is a
// new UUID when a second tenant exists. Not this slice.
const LocalOrgID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

type GrantLevel string

const (
	// Level1: agent may prepare; a human must approve the last step.
	Level1 GrantLevel = "level1"
	// Level2: this identity was donated to agents. No human in the loop.
	Level2 GrantLevel = "level2"
)

type ItemKind string

const (
	ItemAPIKey  ItemKind = "api_key"
	ItemOAuth   ItemKind = "oauth"
	ItemSSH     ItemKind = "ssh"
	ItemFile    ItemKind = "file"
	ItemPasskey ItemKind = "passkey"
)

// Injects is whether Use / child env may touch this kind. SSH stays on the
// agent socket. Files are owner write. Passkeys are the fill host.
func (k ItemKind) Injects() bool {
	switch k {
	case ItemSSH, ItemFile, ItemPasskey:
		return false
	default:
		return true
	}
}

type ActionKind string

const (
	ActionFetch ActionKind = "fetch"
	ActionEnv   ActionKind = "env"
)

type Decision string

const (
	DecisionAllow        Decision = "allow"
	DecisionDeny         Decision = "deny"
	DecisionNeedApproval Decision = "need_approval"
)

type Owner struct {
	Kind OwnerKind `json:"kind"`
	ID   string    `json:"id"`
}

type Principal struct {
	Kind  PrincipalKind `json:"kind"`
	ID    string        `json:"id"`
	OrgID string        `json:"org_id"`
	// Owner is who may create grants for this agent. Humans leave it empty.
	Owner Owner `json:"owner,omitempty"`
}

type Item struct {
	ID    string   `json:"id"`
	OrgID string   `json:"org_id"`
	Name  string   `json:"name"`
	Kind  ItemKind `json:"kind"`
	Owner Owner    `json:"owner"`
	// URIs are the hosts this item may be used against (Infisical "service").
	URIs []string `json:"uris"`
	// Tags are owner labels. Not ACL. Grants are ACL.
	Tags []string `json:"tags,omitempty"`
	// Archived items are hidden from Use, list, fill. History stays.
	Archived bool `json:"archived,omitempty"`
	// HasTOTP is metadata. The seed is not on this struct.
	HasTOTP bool `json:"has_totp,omitempty"`
	// HasFile is metadata. Bytes are not on this struct.
	HasFile bool `json:"has_file,omitempty"`
}

// ItemVersion is history metadata. The sealed blob is not here.
type ItemVersion struct {
	ID     int64
	ItemID string
	Time   time.Time
}

type Grant struct {
	ID        string
	OrgID     string
	AgentID   string
	ItemID    string
	Level     GrantLevel
	Actions   []ActionKind
	ExpiresAt *time.Time
}

type Approval struct {
	ID        string
	GrantID   string
	HumanID   string
	ExpiresAt time.Time
}

// Workload is an Entra-style federation binding. We verify an OIDC ID token
// from someone else's issuer and map (issuer, subject) to an existing agent.
// We do not issue tokens.
type Workload struct {
	AgentID  string
	Issuer   string
	Subject  string
	Audience string
}

type Fetch struct {
	Method string
	URL    string
	Header http.Header
	Body   []byte
}

type UseRequest struct {
	ItemID string
	Action ActionKind
	Fetch  *Fetch
}

type FetchResult struct {
	Status int
	Header http.Header
	Body   []byte
}

type UseResult struct {
	Decision   Decision
	Reason     string
	ApprovalID string
	Fetch      *FetchResult
}

type AuditEvent struct {
	Time       time.Time  `json:"time"`
	OrgID      string     `json:"org_id"`
	AgentID    string     `json:"agent_id"`
	ItemID     string     `json:"item_id"`
	Action     ActionKind `json:"action"`
	Decision   Decision   `json:"decision"`
	Reason     string     `json:"reason,omitempty"`
	ApprovalID string     `json:"approval_id,omitempty"`
}
