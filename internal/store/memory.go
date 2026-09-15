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
	workloads map[string]protocol.Workload // key: issuer+"\x00"+subject
	versions  []protocol.ItemVersion
	verSecret map[int64]Secret
	nextVer   int64
}

func NewMemory() *Memory {
	return &Memory{
		agents:    map[string]protocol.Principal{},
		humans:    map[string]protocol.Principal{},
		items:     map[string]protocol.Item{},
		secrets:   map[string]Secret{},
		grants:    map[string]protocol.Grant{},
		approvals: map[string]protocol.Approval{},
		workloads: map[string]protocol.Workload{},
		verSecret: map[int64]Secret{},
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

func (m *Memory) ListHumans() ([]protocol.Principal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]protocol.Principal, 0, len(m.humans))
	for _, p := range m.humans {
		out = append(out, p)
	}
	return out, nil
}

func (m *Memory) PutItem(item protocol.Item, secret Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.secrets[item.ID]; ok {
		m.nextVer++
		id := m.nextVer
		cp := make(Secret, len(old))
		copy(cp, old)
		m.verSecret[id] = cp
		m.versions = append(m.versions, protocol.ItemVersion{ID: id, ItemID: item.ID, Time: time.Now().UTC()})
	}
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
		if item.Archived {
			continue
		}
		out = append(out, item)
	}
	return out, nil
}

func (m *Memory) ArchiveItem(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.items[id]
	if !ok {
		return ErrNotFound
	}
	item.Archived = true
	m.items[id] = item
	return nil
}

func (m *Memory) DeleteItem(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.items[id]; !ok {
		return ErrNotFound
	}
	delete(m.items, id)
	delete(m.secrets, id)
	for k, g := range m.grants {
		if g.ItemID == id {
			delete(m.grants, k)
		}
	}
	kept := m.versions[:0]
	for _, v := range m.versions {
		if v.ItemID == id {
			delete(m.verSecret, v.ID)
			continue
		}
		kept = append(kept, v)
	}
	m.versions = kept
	return nil
}

func (m *Memory) Versions(itemID string) ([]protocol.ItemVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []protocol.ItemVersion
	for _, v := range m.versions {
		if v.ItemID == itemID {
			out = append(out, v)
		}
	}
	return out, nil
}

func (m *Memory) RestoreVersion(itemID string, versionID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.items[itemID]
	if !ok {
		return ErrNotFound
	}
	sec, ok := m.verSecret[versionID]
	if !ok {
		return ErrNotFound
	}
	found := false
	for _, v := range m.versions {
		if v.ID == versionID && v.ItemID == itemID {
			found = true
			break
		}
	}
	if !found {
		return ErrNotFound
	}
	if old, ok := m.secrets[itemID]; ok {
		m.nextVer++
		nid := m.nextVer
		cp := make(Secret, len(old))
		copy(cp, old)
		m.verSecret[nid] = cp
		m.versions = append(m.versions, protocol.ItemVersion{ID: nid, ItemID: itemID, Time: time.Now().UTC()})
	}
	n := make(Secret, len(sec))
	copy(n, sec)
	m.secrets[itemID] = n
	m.items[itemID] = item
	return nil
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

func workloadKey(issuer, subject string) string { return issuer + "\x00" + subject }

func (m *Memory) PutWorkload(w protocol.Workload) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workloads[workloadKey(w.Issuer, w.Subject)] = w
	return nil
}

func (m *Memory) Workload(issuer, subject string) (*protocol.Workload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.workloads[workloadKey(issuer, subject)]
	if !ok {
		return nil, nil
	}
	cp := w
	return &cp, nil
}

func (m *Memory) WorkloadsForIssuer(issuer string) ([]protocol.Workload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []protocol.Workload
	for _, w := range m.workloads {
		if w.Issuer == issuer {
			out = append(out, w)
		}
	}
	return out, nil
}
