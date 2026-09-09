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

type GrantLevel string

const (
	// Level1: agent may prepare; a human must approve the last step.
	Level1 GrantLevel = "level1"
	// Level2: this identity was donated to agents. No human in the loop.
	Level2 GrantLevel = "level2"
)

type ItemKind string

const (
	ItemAPIKey ItemKind = "api_key"
)

type ActionKind string

const (
	ActionFetch ActionKind = "fetch"
)

type Decision string

const (
	DecisionAllow        Decision = "allow"
	DecisionDeny         Decision = "deny"
	DecisionNeedApproval Decision = "need_approval"
)

type Owner struct {
	Kind OwnerKind
	ID   string
}

type Principal struct {
	Kind  PrincipalKind
	ID    string
	OrgID string
}

type Item struct {
	ID    string
	OrgID string
	Name  string
	Kind  ItemKind
	Owner Owner
	// URIs are the hosts this item may be used against (Infisical "service").
	URIs []string
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

type Fetch struct {
	Method string
	URL    string
	Header map[string][]string
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
	Time       time.Time
	OrgID      string
	AgentID    string
	ItemID     string
	Action     ActionKind
	Decision   Decision
	Reason     string
	ApprovalID string
}
