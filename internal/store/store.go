package store

import (
	"errors"
	"time"

	"github.com/vortexnyc/password-manager/internal/protocol"
)

const maxListResults = 10000

var (
	ErrNotFound = errors.New("store: not found")
	ErrDenied   = errors.New("store: denied")
)

// Secret is vault material. It never lives on protocol types.
type Secret []byte

// UseAuth is the consolidated authorization snapshot for a single Use call.
// It is returned by Store.UseAuth in one round trip and contains no secret.
type UseAuth struct {
	Agent    protocol.Principal
	Item     protocol.Item
	Grant    *protocol.Grant
	Approval *protocol.Approval
}

type Store interface {
	PutAgent(protocol.Principal) error
	Agent(id string) (protocol.Principal, error)
	ListAgents() ([]protocol.Principal, error)
	// RevokeAgent sets RevokedAt on the agent. It is idempotent and preserves
	// the earliest revocation time. It returns ErrNotFound if the agent does not exist.
	// If one or more audit events are provided, they are appended atomically with
	// the revocation in the same store transaction.
	RevokeAgent(id string, at time.Time, audit ...protocol.AuditEvent) error

	PutHuman(protocol.Principal) error
	Human(id string) (protocol.Principal, error)
	ListHumans() ([]protocol.Principal, error)

	PutItem(protocol.Item, Secret) error
	Item(id string) (protocol.Item, error)
	ItemByName(orgID, name string) (protocol.Item, error)
	ListItems() ([]protocol.Item, error)
	ArchiveItem(id string) error
	DeleteItem(id string) error
	Versions(itemID string) ([]protocol.ItemVersion, error)
	RestoreVersion(itemID string, versionID int64) error
	// Secret is for the broker only. There is no agent-facing reveal.
	Secret(id string) (Secret, error)
	// UseAuth returns the agent, item, grant, and live approval for a Use
	// request in a single round trip. It never returns a secret.
	UseAuth(agentID, itemID string, now time.Time) (UseAuth, error)

	PutGrant(protocol.Grant) error
	Grant(id string) (*protocol.Grant, error)
	GrantFor(agentID, itemID string) (*protocol.Grant, error)
	ListGrants() ([]protocol.Grant, error)

	PutApproval(protocol.Approval) error
	LiveApproval(grantID string, now time.Time) (*protocol.Approval, error)

	PutWorkload(protocol.Workload) error
	Workload(issuer, subject string) (*protocol.Workload, error)
	WorkloadsForIssuer(issuer string) ([]protocol.Workload, error)

	PutSession(s protocol.Session, secretHash []byte) error
	SessionByHash(secretHash []byte) (protocol.Session, error)
	ListSessions() ([]protocol.Session, error)

	AppendAudit(protocol.AuditEvent) error
	AppendAudits([]protocol.AuditEvent) error
	Audit() ([]protocol.AuditEvent, error)
	Close() error
}
