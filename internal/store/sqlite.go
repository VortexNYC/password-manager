package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/vortexnyc/password-manager/internal/crypto"
	"github.com/vortexnyc/password-manager/internal/protocol"

	_ "modernc.org/sqlite"
)

type SQLite struct {
	db   *sql.DB
	key  []byte
	mu   sync.Mutex
	deks map[string][]byte
}

func OpenSQLite(path string, key []byte) (*SQLite, error) {
	if len(key) != crypto.KeySize {
		return nil, fmt.Errorf("store: key must be %d bytes", crypto.KeySize)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &SQLite{db: db, key: append([]byte(nil), key...), deks: map[string][]byte{}}
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
			has_totp INTEGER NOT NULL DEFAULT 0
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
		`CREATE TABLE IF NOT EXISTS workloads (
			issuer TEXT NOT NULL,
			subject TEXT NOT NULL,
			agent_id TEXT NOT NULL,
			audience TEXT NOT NULL,
			PRIMARY KEY (issuer, subject)
		)`,
		`CREATE TABLE IF NOT EXISTS owner_keys (
			owner_kind TEXT NOT NULL,
			owner_id TEXT NOT NULL,
			wrapped BLOB NOT NULL,
			PRIMARY KEY (owner_kind, owner_id)
		)`,
		`CREATE TABLE IF NOT EXISTS item_versions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			item_id TEXT NOT NULL,
			at TEXT NOT NULL,
			secret BLOB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			agent_id TEXT NOT NULL,
			secret_hash BLOB NOT NULL,
			expires_at INTEGER NOT NULL,
			UNIQUE(secret_hash)
		)`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	_, _ = s.db.Exec(`ALTER TABLE items ADD COLUMN has_totp INTEGER NOT NULL DEFAULT 0`)
	_, _ = s.db.Exec(`ALTER TABLE agents ADD COLUMN owner_kind TEXT NOT NULL DEFAULT ''`)
	_, _ = s.db.Exec(`ALTER TABLE agents ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''`)
	_, _ = s.db.Exec(`ALTER TABLE agents ADD COLUMN revoked_at TEXT`)
	_, _ = s.db.Exec(`ALTER TABLE items ADD COLUMN tags TEXT NOT NULL DEFAULT '[]'`)
	_, _ = s.db.Exec(`ALTER TABLE items ADD COLUMN archived INTEGER NOT NULL DEFAULT 0`)
	_, _ = s.db.Exec(`ALTER TABLE items ADD COLUMN has_file INTEGER NOT NULL DEFAULT 0`)
	_, _ = s.db.Exec(`ALTER TABLE items ADD COLUMN login TEXT NOT NULL DEFAULT ''`)
	if err := s.dropItemsNameUnique(); err != nil {
		return err
	}
	return s.rewrapLegacy()
}

func (s *SQLite) dropItemsNameUnique() error {
	var schema string
	if err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='items'`).Scan(&schema); err != nil {
		return err
	}
	compact := strings.ReplaceAll(schema, " ", "")
	if !strings.Contains(compact, "UNIQUE(org_id,name)") {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`CREATE TABLE items_noidx (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			name TEXT NOT NULL,
			kind TEXT NOT NULL,
			owner_kind TEXT NOT NULL,
			owner_id TEXT NOT NULL,
			uris TEXT NOT NULL,
			secret BLOB NOT NULL,
			has_totp INTEGER NOT NULL DEFAULT 0,
			tags TEXT NOT NULL DEFAULT '[]',
			archived INTEGER NOT NULL DEFAULT 0,
			has_file INTEGER NOT NULL DEFAULT 0,
			login TEXT NOT NULL DEFAULT ''
		)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO items_noidx(id, org_id, name, kind, owner_kind, owner_id, uris, secret, has_totp, tags, archived, has_file, login)
		SELECT id, org_id, name, kind, owner_kind, owner_id, uris, secret, has_totp, tags, archived, has_file, login FROM items`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DROP TABLE items`); err != nil {
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE items_noidx RENAME TO items`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite) Close() error { return s.db.Close() }

func revokedAtString(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: t.UTC().Format(time.RFC3339), Valid: true}
}

func parseRevokedAt(s sql.NullString) (*time.Time, error) {
	if !s.Valid || s.String == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, s.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *SQLite) PutAgent(p protocol.Principal) error {
	rv := revokedAtString(p.RevokedAt)
	_, err := s.db.Exec(`INSERT INTO agents(id, org_id, owner_kind, owner_id, revoked_at) VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET org_id=excluded.org_id, owner_kind=excluded.owner_kind, owner_id=excluded.owner_id, revoked_at=COALESCE(agents.revoked_at, excluded.revoked_at)`,
		p.ID, p.OrgID, p.Owner.Kind, p.Owner.ID, rv)
	return err
}

func (s *SQLite) Agent(id string) (protocol.Principal, error) {
	var p protocol.Principal
	p.Kind = protocol.PrincipalAgent
	var ownerKind, ownerID, revokedAt sql.NullString
	err := s.db.QueryRow(`SELECT id, org_id, owner_kind, owner_id, revoked_at FROM agents WHERE id=?`, id).Scan(&p.ID, &p.OrgID, &ownerKind, &ownerID, &revokedAt)
	if err == sql.ErrNoRows {
		return protocol.Principal{}, ErrNotFound
	}
	if err != nil {
		return protocol.Principal{}, err
	}
	p.Owner.Kind = protocol.OwnerKind(ownerKind.String)
	p.Owner.ID = ownerID.String
	rv, err := parseRevokedAt(revokedAt)
	if err != nil {
		return protocol.Principal{}, err
	}
	p.RevokedAt = rv
	return p, nil
}

func (s *SQLite) ListAgents() ([]protocol.Principal, error) {
	rows, err := s.db.Query(`SELECT id, org_id, owner_kind, owner_id, revoked_at FROM agents ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Principal
	for rows.Next() {
		var p protocol.Principal
		p.Kind = protocol.PrincipalAgent
		var ownerKind, ownerID, revokedAt sql.NullString
		if err := rows.Scan(&p.ID, &p.OrgID, &ownerKind, &ownerID, &revokedAt); err != nil {
			return nil, err
		}
		p.Owner.Kind = protocol.OwnerKind(ownerKind.String)
		p.Owner.ID = ownerID.String
		rv, err := parseRevokedAt(revokedAt)
		if err != nil {
			return nil, err
		}
		p.RevokedAt = rv
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLite) RevokeAgent(id string, at time.Time, audit ...protocol.AuditEvent) error {
	if len(audit) == 0 {
		rv := at.UTC().Format(time.RFC3339)
		res, err := s.db.Exec(`UPDATE agents SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`, rv, id)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	rv := at.UTC().Format(time.RFC3339)
	res, err := tx.Exec(`UPDATE agents SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`, rv, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}

	for _, e := range audit {
		if _, err := tx.Exec(`INSERT INTO audit(at, org_id, agent_id, item_id, action, decision, reason, approval_id)
			VALUES(?,?,?,?,?,?,?,?)`,
			e.Time.UTC().Format(time.RFC3339Nano), e.OrgID, e.AgentID, e.ItemID, e.Action, e.Decision, e.Reason, e.ApprovalID); err != nil {
			return err
		}
	}

	return tx.Commit()
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

func (s *SQLite) ListHumans() ([]protocol.Principal, error) {
	rows, err := s.db.Query(`SELECT id, org_id FROM humans ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Principal
	for rows.Next() {
		var p protocol.Principal
		p.Kind = protocol.PrincipalHuman
		if err := rows.Scan(&p.ID, &p.OrgID); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLite) snapshot(id string) error {
	var blob []byte
	err := s.db.QueryRow(`SELECT secret FROM items WHERE id=?`, id).Scan(&blob)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO item_versions(item_id, at, secret) VALUES(?,?,?)`,
		id, time.Now().UTC().Format(time.RFC3339Nano), blob)
	return err
}

func (s *SQLite) PutItem(item protocol.Item, secret Secret) error {
	if err := s.snapshot(item.ID); err != nil {
		return err
	}
	uris, err := json.Marshal(item.URIs)
	if err != nil {
		return err
	}
	if item.URIs == nil {
		uris = []byte("[]")
	}
	tags, err := json.Marshal(item.Tags)
	if err != nil {
		return err
	}
	if item.Tags == nil {
		tags = []byte("[]")
	}
	dek, err := s.ownerDEK(item.Owner)
	if err != nil {
		return err
	}
	blob, err := crypto.Seal(dek, secret)
	if err != nil {
		return err
	}
	has := 0
	if item.HasTOTP {
		has = 1
	}
	arch := 0
	if item.Archived {
		arch = 1
	}
	hf := 0
	if item.HasFile {
		hf = 1
	}
	_, err = s.db.Exec(`INSERT INTO items(id, org_id, name, kind, owner_kind, owner_id, uris, secret, has_totp, tags, archived, has_file, login)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			org_id=excluded.org_id, name=excluded.name, kind=excluded.kind,
			owner_kind=excluded.owner_kind, owner_id=excluded.owner_id,
			uris=excluded.uris, secret=excluded.secret, has_totp=excluded.has_totp,
			tags=excluded.tags, archived=excluded.archived, has_file=excluded.has_file,
			login=excluded.login`,
		item.ID, item.OrgID, item.Name, item.Kind, item.Owner.Kind, item.Owner.ID, uris, blob, has, tags, arch, hf, item.Login)
	return err
}

func (s *SQLite) scanItem(scan func(dest ...any) error) (protocol.Item, error) {
	var item protocol.Item
	var uris, tags []byte
	var has, arch, hf int
	err := scan(&item.ID, &item.OrgID, &item.Name, &item.Kind, &item.Owner.Kind, &item.Owner.ID, &uris, &has, &tags, &arch, &hf, &item.Login)
	if err == sql.ErrNoRows {
		return protocol.Item{}, ErrNotFound
	}
	if err != nil {
		return protocol.Item{}, err
	}
	if len(uris) > 0 {
		_ = json.Unmarshal(uris, &item.URIs)
	}
	if len(tags) > 0 {
		_ = json.Unmarshal(tags, &item.Tags)
	}
	item.HasTOTP = has != 0
	item.Archived = arch != 0
	item.HasFile = hf != 0
	return item, nil
}

func (s *SQLite) Item(id string) (protocol.Item, error) {
	row := s.db.QueryRow(`SELECT id, org_id, name, kind, owner_kind, owner_id, uris, has_totp, tags, archived, has_file, login FROM items WHERE id=?`, id)
	return s.scanItem(row.Scan)
}

func (s *SQLite) ItemByName(orgID, name string) (protocol.Item, error) {
	row := s.db.QueryRow(`SELECT id, org_id, name, kind, owner_kind, owner_id, uris, has_totp, tags, archived, has_file, login FROM items WHERE org_id=? AND name=?`, orgID, name)
	return s.scanItem(row.Scan)
}

func (s *SQLite) ListItems() ([]protocol.Item, error) {
	rows, err := s.db.Query(`SELECT id, org_id, name, kind, owner_kind, owner_id, uris, has_totp, tags, archived, has_file, login FROM items WHERE archived=0 ORDER BY name`)
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

func (s *SQLite) ArchiveItem(id string) error {
	res, err := s.db.Exec(`UPDATE items SET archived=1 WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) DeleteItem(id string) error {
	if _, err := s.db.Exec(`DELETE FROM item_versions WHERE item_id=?`, id); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM grants WHERE item_id=?`, id); err != nil {
		return err
	}
	res, err := s.db.Exec(`DELETE FROM items WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) Versions(itemID string) ([]protocol.ItemVersion, error) {
	rows, err := s.db.Query(`SELECT id, item_id, at FROM item_versions WHERE item_id=? ORDER BY id`, itemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.ItemVersion
	for rows.Next() {
		var v protocol.ItemVersion
		var at string
		if err := rows.Scan(&v.ID, &v.ItemID, &at); err != nil {
			return nil, err
		}
		v.Time, _ = time.Parse(time.RFC3339Nano, at)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLite) RestoreVersion(itemID string, versionID int64) error {
	if err := s.snapshot(itemID); err != nil {
		return err
	}
	var blob []byte
	err := s.db.QueryRow(`SELECT secret FROM item_versions WHERE id=? AND item_id=?`, versionID, itemID).Scan(&blob)
	if err == sql.ErrNoRows {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE items SET secret=? WHERE id=?`, blob, itemID)
	return err
}

func (s *SQLite) Secret(id string) (Secret, error) {
	var blob []byte
	var owner protocol.Owner
	err := s.db.QueryRow(`SELECT secret, owner_kind, owner_id FROM items WHERE id=?`, id).Scan(&blob, &owner.Kind, &owner.ID)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	dek, err := s.ownerDEK(owner)
	if err != nil {
		return nil, err
	}
	plain, err := crypto.Open(dek, blob)
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

func (s *SQLite) PutWorkload(w protocol.Workload) error {
	_, err := s.db.Exec(`INSERT INTO workloads(issuer, subject, agent_id, audience)
		VALUES(?,?,?,?)
		ON CONFLICT(issuer, subject) DO UPDATE SET
			agent_id=excluded.agent_id, audience=excluded.audience`,
		w.Issuer, w.Subject, w.AgentID, w.Audience)
	return err
}

func (s *SQLite) Workload(issuer, subject string) (*protocol.Workload, error) {
	var w protocol.Workload
	err := s.db.QueryRow(`SELECT agent_id, issuer, subject, audience FROM workloads WHERE issuer=? AND subject=?`, issuer, subject).
		Scan(&w.AgentID, &w.Issuer, &w.Subject, &w.Audience)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &w, nil
}

func (s *SQLite) WorkloadsForIssuer(issuer string) ([]protocol.Workload, error) {
	rows, err := s.db.Query(`SELECT agent_id, issuer, subject, audience FROM workloads WHERE issuer=?`, issuer)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Workload
	for rows.Next() {
		var w protocol.Workload
		if err := rows.Scan(&w.AgentID, &w.Issuer, &w.Subject, &w.Audience); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *SQLite) PutSession(sess protocol.Session, secretHash []byte) error {
	_, err := s.db.Exec(`INSERT INTO sessions(id, org_id, agent_id, secret_hash, expires_at)
		VALUES(?,?,?,?,?)`,
		sess.ID, sess.OrgID, sess.AgentID, secretHash, sess.ExpiresAt.UTC().Unix())
	return err
}

func (s *SQLite) SessionByHash(secretHash []byte) (protocol.Session, error) {
	var sess protocol.Session
	var exp int64
	err := s.db.QueryRow(`SELECT id, org_id, agent_id, expires_at FROM sessions WHERE secret_hash=?`, secretHash).
		Scan(&sess.ID, &sess.OrgID, &sess.AgentID, &exp)
	if err == sql.ErrNoRows {
		return protocol.Session{}, ErrNotFound
	}
	if err != nil {
		return protocol.Session{}, err
	}
	sess.ExpiresAt = time.Unix(exp, 0).UTC()
	return sess, nil
}

func (s *SQLite) ListSessions() ([]protocol.Session, error) {
	rows, err := s.db.Query(`SELECT id, org_id, agent_id, expires_at FROM sessions ORDER BY expires_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Session
	for rows.Next() {
		var sess protocol.Session
		var exp int64
		if err := rows.Scan(&sess.ID, &sess.OrgID, &sess.AgentID, &exp); err != nil {
			return nil, err
		}
		sess.ExpiresAt = time.Unix(exp, 0).UTC()
		out = append(out, sess)
	}
	return out, rows.Err()
}
