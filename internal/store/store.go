package store

import (
	"errors"
	"time"

	"github.com/vortexnyc/password-manager/internal/protocol"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrDenied   = errors.New("store: denied")
)

// Secret is vault material. It never lives on protocol types.
type Secret []byte

type Store interface {
	PutAgent(protocol.Principal) error
	Agent(id string) (protocol.Principal, error)
	ListAgents() ([]protocol.Principal, error)

	PutHuman(protocol.Principal) error
	Human(id string) (protocol.Principal, error)

	PutItem(protocol.Item, Secret) error
	Item(id string) (protocol.Item, error)
	ItemByName(orgID, name string) (protocol.Item, error)
	ListItems() ([]protocol.Item, error)
	// Secret is for the broker only. There is no agent-facing reveal.
	Secret(id string) (Secret, error)

	PutGrant(protocol.Grant) error
	Grant(id string) (*protocol.Grant, error)
	GrantFor(agentID, itemID string) (*protocol.Grant, error)
	ListGrants() ([]protocol.Grant, error)

	PutApproval(protocol.Approval) error
	LiveApproval(grantID string, now time.Time) (*protocol.Approval, error)

	AppendAudit(protocol.AuditEvent) error
	Audit() ([]protocol.AuditEvent, error)
	Close() error
}
