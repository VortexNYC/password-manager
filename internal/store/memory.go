package store

import (
	"sync"
	"time"

	"github.com/vortexnyc/password-manager/internal/protocol"
)

type Memory struct {
	mu        sync.Mutex
	agents    map[string]protocol.Principal
	humans    map[string]protocol.Principal
	items     map[string]protocol.Item
	secrets   map[string]Secret
	grants    map[string]protocol.Grant // key: agentID+"\x00"+itemID
	approvals map[string]protocol.Approval
	audit     []protocol.AuditEvent
}

func NewMemory() *Memory {
	return &Memory{
		agents:    map[string]protocol.Principal{},
		humans:    map[string]protocol.Principal{},
		items:     map[string]protocol.Item{},
		secrets:   map[string]Secret{},
		grants:    map[string]protocol.Grant{},
		approvals: map[string]protocol.Approval{},
	}
}

func grantKey(agentID, itemID string) string { return agentID + "\x00" + itemID }

func (m *Memory) Close() error { return nil }

func (m *Memory) PutAgent(p protocol.Principal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.agents[p.ID] = p
	return nil
}

func (m *Memory) ListAgents() ([]protocol.Principal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]protocol.Principal, 0, len(m.agents))
	for _, p := range m.agents {
		out = append(out, p)
	}
	return out, nil
}

func (m *Memory) Agent(id string) (protocol.Principal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.agents[id]
	if !ok {
		return protocol.Principal{}, ErrNotFound
	}
	return p, nil
}

func (m *Memory) PutHuman(p protocol.Principal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.humans[p.ID] = p
	return nil
}

func (m *Memory) Human(id string) (protocol.Principal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.humans[id]
	if !ok {
		return protocol.Principal{}, ErrNotFound
	}
	return p, nil
}

func (m *Memory) PutItem(item protocol.Item, secret Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[item.ID] = item
	m.secrets[item.ID] = append(Secret(nil), secret...)
	return nil
}

func (m *Memory) Item(id string) (protocol.Item, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.items[id]
	if !ok {
		return protocol.Item{}, ErrNotFound
	}
	return item, nil
}

func (m *Memory) ItemByName(orgID, name string) (protocol.Item, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, item := range m.items {
		if item.OrgID == orgID && item.Name == name {
			return item, nil
		}
	}
	return protocol.Item{}, ErrNotFound
}

func (m *Memory) ListItems() ([]protocol.Item, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]protocol.Item, 0, len(m.items))
	for _, item := range m.items {
		out = append(out, item)
	}
	return out, nil
}

func (m *Memory) Secret(id string) (Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.secrets[id]
	if !ok {
		return nil, ErrNotFound
	}
	out := make(Secret, len(s))
	copy(out, s)
	return out, nil
}

func (m *Memory) PutGrant(g protocol.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.grants[grantKey(g.AgentID, g.ItemID)] = g
	return nil
}

func (m *Memory) Grant(id string) (*protocol.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, g := range m.grants {
		if g.ID == id {
			cp := g
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) GrantFor(agentID, itemID string) (*protocol.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[grantKey(agentID, itemID)]
	if !ok {
		return nil, nil
	}
	cp := g
	return &cp, nil
}

func (m *Memory) ListGrants() ([]protocol.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]protocol.Grant, 0, len(m.grants))
	for _, g := range m.grants {
		out = append(out, g)
	}
	return out, nil
}

func (m *Memory) PutApproval(a protocol.Approval) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.approvals[a.GrantID] = a
	return nil
}

func (m *Memory) LiveApproval(grantID string, now time.Time) (*protocol.Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.approvals[grantID]
	if !ok {
		return nil, nil
	}
	if !now.Before(a.ExpiresAt) {
		return nil, nil
	}
	cp := a
	return &cp, nil
}

func (m *Memory) AppendAudit(e protocol.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audit = append(m.audit, e)
	return nil
}

func (m *Memory) Audit() ([]protocol.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]protocol.AuditEvent, len(m.audit))
	copy(out, m.audit)
	return out, nil
}
