package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vortexnyc/password-manager/internal/crypto"
	"github.com/vortexnyc/password-manager/internal/protocol"

	_ "modernc.org/sqlite"
)

type SQLite struct {
	db  *sql.DB
	key []byte
}

func OpenSQLite(path string, key []byte) (*SQLite, error) {
	if len(key) != crypto.KeySize {
		return nil, fmt.Errorf("store: key must be %d bytes", crypto.KeySize)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &SQLite{db: db, key: append([]byte(nil), key...)}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLite) migrate() error {
	for _, q := range []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA journal_mode = WAL`,
		`CREATE TABLE IF NOT EXISTS humans (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS agents (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS items (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			name TEXT NOT NULL,
			kind TEXT NOT NULL,
			owner_kind TEXT NOT NULL,
			owner_id TEXT NOT NULL,
			uris TEXT NOT NULL,
			secret BLOB NOT NULL,
			UNIQUE(org_id, name)
		)`,
		`CREATE TABLE IF NOT EXISTS grants (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			agent_id TEXT NOT NULL,
			item_id TEXT NOT NULL,
			level TEXT NOT NULL,
			actions TEXT NOT NULL,
			expires_at INTEGER,
			UNIQUE(agent_id, item_id)
		)`,
		`CREATE TABLE IF NOT EXISTS approvals (
			grant_id TEXT PRIMARY KEY,
			id TEXT NOT NULL,
			human_id TEXT NOT NULL,
			expires_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS audit (
			rowid INTEGER PRIMARY KEY AUTOINCREMENT,
			at TEXT NOT NULL,
			org_id TEXT NOT NULL,
			agent_id TEXT NOT NULL,
			item_id TEXT NOT NULL,
			action TEXT NOT NULL,
			decision TEXT NOT NULL,
			reason TEXT NOT NULL,
			approval_id TEXT NOT NULL
		)`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLite) Close() error { return s.db.Close() }

func (s *SQLite) PutAgent(p protocol.Principal) error {
	_, err := s.db.Exec(`INSERT INTO agents(id, org_id) VALUES(?, ?)
		ON CONFLICT(id) DO UPDATE SET org_id=excluded.org_id`, p.ID, p.OrgID)
	return err
}

func (s *SQLite) Agent(id string) (protocol.Principal, error) {
	var p protocol.Principal
	p.Kind = protocol.PrincipalAgent
	err := s.db.QueryRow(`SELECT id, org_id FROM agents WHERE id=?`, id).Scan(&p.ID, &p.OrgID)
	if err == sql.ErrNoRows {
		return protocol.Principal{}, ErrNotFound
	}
	return p, err
}

func (s *SQLite) ListAgents() ([]protocol.Principal, error) {
	rows, err := s.db.Query(`SELECT id, org_id FROM agents ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Principal
	for rows.Next() {
		var p protocol.Principal
		p.Kind = protocol.PrincipalAgent
		if err := rows.Scan(&p.ID, &p.OrgID); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLite) PutHuman(p protocol.Principal) error {
	_, err := s.db.Exec(`INSERT INTO humans(id, org_id) VALUES(?, ?)
		ON CONFLICT(id) DO UPDATE SET org_id=excluded.org_id`, p.ID, p.OrgID)
	return err
}

func (s *SQLite) Human(id string) (protocol.Principal, error) {
	var p protocol.Principal
	p.Kind = protocol.PrincipalHuman
	err := s.db.QueryRow(`SELECT id, org_id FROM humans WHERE id=?`, id).Scan(&p.ID, &p.OrgID)
	if err == sql.ErrNoRows {
		return protocol.Principal{}, ErrNotFound
	}
	return p, err
}

func (s *SQLite) PutItem(item protocol.Item, secret Secret) error {
	uris, err := json.Marshal(item.URIs)
	if err != nil {
		return err
	}
	if item.URIs == nil {
		uris = []byte("[]")
	}
	blob, err := crypto.Seal(s.key, secret)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO items(id, org_id, name, kind, owner_kind, owner_id, uris, secret)
		VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			org_id=excluded.org_id, name=excluded.name, kind=excluded.kind,
			owner_kind=excluded.owner_kind, owner_id=excluded.owner_id,
			uris=excluded.uris, secret=excluded.secret`,
		item.ID, item.OrgID, item.Name, item.Kind, item.Owner.Kind, item.Owner.ID, uris, blob)
	return err
}

func (s *SQLite) scanItem(scan func(dest ...any) error) (protocol.Item, error) {
	var item protocol.Item
	var uris []byte
	err := scan(&item.ID, &item.OrgID, &item.Name, &item.Kind, &item.Owner.Kind, &item.Owner.ID, &uris)
	if err == sql.ErrNoRows {
		return protocol.Item{}, ErrNotFound
	}
	if err != nil {
		return protocol.Item{}, err
	}
	if len(uris) > 0 {
		_ = json.Unmarshal(uris, &item.URIs)
	}
	return item, nil
}

func (s *SQLite) Item(id string) (protocol.Item, error) {
	row := s.db.QueryRow(`SELECT id, org_id, name, kind, owner_kind, owner_id, uris FROM items WHERE id=?`, id)
	return s.scanItem(row.Scan)
}

func (s *SQLite) ItemByName(orgID, name string) (protocol.Item, error) {
	row := s.db.QueryRow(`SELECT id, org_id, name, kind, owner_kind, owner_id, uris FROM items WHERE org_id=? AND name=?`, orgID, name)
	return s.scanItem(row.Scan)
}

func (s *SQLite) ListItems() ([]protocol.Item, error) {
	rows, err := s.db.Query(`SELECT id, org_id, name, kind, owner_kind, owner_id, uris FROM items ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Item
	for rows.Next() {
		item, err := s.scanItem(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLite) Secret(id string) (Secret, error) {
	var blob []byte
	err := s.db.QueryRow(`SELECT secret FROM items WHERE id=?`, id).Scan(&blob)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	plain, err := crypto.Open(s.key, blob)
	if err != nil {
		return nil, err
	}
	return Secret(plain), nil
}

func (s *SQLite) PutGrant(g protocol.Grant) error {
	actions, err := json.Marshal(g.Actions)
	if err != nil {
		return err
	}
	var exp any
	if g.ExpiresAt != nil {
		exp = g.ExpiresAt.Unix()
	}
	_, err = s.db.Exec(`INSERT INTO grants(id, org_id, agent_id, item_id, level, actions, expires_at)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(agent_id, item_id) DO UPDATE SET
			id=excluded.id, org_id=excluded.org_id, level=excluded.level,
			actions=excluded.actions, expires_at=excluded.expires_at`,
		g.ID, g.OrgID, g.AgentID, g.ItemID, g.Level, actions, exp)
	return err
}

func scanGrant(scan func(dest ...any) error) (*protocol.Grant, error) {
	var g protocol.Grant
	var actions []byte
	var exp sql.NullInt64
	err := scan(&g.ID, &g.OrgID, &g.AgentID, &g.ItemID, &g.Level, &actions, &exp)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(actions) > 0 {
		_ = json.Unmarshal(actions, &g.Actions)
	}
	if exp.Valid {
		t := time.Unix(exp.Int64, 0).UTC()
		g.ExpiresAt = &t
	}
	return &g, nil
}

func (s *SQLite) Grant(id string) (*protocol.Grant, error) {
	row := s.db.QueryRow(`SELECT id, org_id, agent_id, item_id, level, actions, expires_at FROM grants WHERE id=?`, id)
	return scanGrant(row.Scan)
}

func (s *SQLite) GrantFor(agentID, itemID string) (*protocol.Grant, error) {
	row := s.db.QueryRow(`SELECT id, org_id, agent_id, item_id, level, actions, expires_at FROM grants WHERE agent_id=? AND item_id=?`, agentID, itemID)
	g, err := scanGrant(row.Scan)
	if err == ErrNotFound {
		return nil, nil
	}
	return g, err
}

func (s *SQLite) ListGrants() ([]protocol.Grant, error) {
	rows, err := s.db.Query(`SELECT id, org_id, agent_id, item_id, level, actions, expires_at FROM grants ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Grant
	for rows.Next() {
		g, err := scanGrant(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

func (s *SQLite) PutApproval(a protocol.Approval) error {
	_, err := s.db.Exec(`INSERT INTO approvals(grant_id, id, human_id, expires_at) VALUES(?,?,?,?)
		ON CONFLICT(grant_id) DO UPDATE SET id=excluded.id, human_id=excluded.human_id, expires_at=excluded.expires_at`,
		a.GrantID, a.ID, a.HumanID, a.ExpiresAt.Unix())
	return err
}

func (s *SQLite) LiveApproval(grantID string, now time.Time) (*protocol.Approval, error) {
	var a protocol.Approval
	var exp int64
	err := s.db.QueryRow(`SELECT grant_id, id, human_id, expires_at FROM approvals WHERE grant_id=?`, grantID).
		Scan(&a.GrantID, &a.ID, &a.HumanID, &exp)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.ExpiresAt = time.Unix(exp, 0).UTC()
	if !now.Before(a.ExpiresAt) {
		return nil, nil
	}
	return &a, nil
}

func (s *SQLite) AppendAudit(e protocol.AuditEvent) error {
	_, err := s.db.Exec(`INSERT INTO audit(at, org_id, agent_id, item_id, action, decision, reason, approval_id)
		VALUES(?,?,?,?,?,?,?,?)`,
		e.Time.UTC().Format(time.RFC3339Nano), e.OrgID, e.AgentID, e.ItemID, e.Action, e.Decision, e.Reason, e.ApprovalID)
	return err
}

func (s *SQLite) Audit() ([]protocol.AuditEvent, error) {
	rows, err := s.db.Query(`SELECT at, org_id, agent_id, item_id, action, decision, reason, approval_id FROM audit ORDER BY rowid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.AuditEvent
	for rows.Next() {
		var e protocol.AuditEvent
		var at string
		if err := rows.Scan(&at, &e.OrgID, &e.AgentID, &e.ItemID, &e.Action, &e.Decision, &e.Reason, &e.ApprovalID); err != nil {
			return nil, err
		}
		e.Time, _ = time.Parse(time.RFC3339Nano, at)
		out = append(out, e)
	}
	return out, rows.Err()
}
