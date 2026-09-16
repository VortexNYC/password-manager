package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vortexnyc/password-manager/internal/crypto"
	"github.com/vortexnyc/password-manager/internal/protocol"
)

// pgConn is the surface we need from a pgx connection or transaction.
type pgConn interface {
	Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...interface{}) pgx.Row
	Query(context.Context, string, ...interface{}) (pgx.Rows, error)
}

// Postgres is a pgx-backed Store for the origin. Secrets are encrypted with
// per-owner data keys before they are written, same as the SQLite store.
type Postgres struct {
	pool *pgxpool.Pool
	km   *keyManager
}

// OpenPostgres opens a Postgres-backed store. The supplied key is the master
// key used to wrap per-owner data encryption keys. No key material is persisted.
func OpenPostgres(connString string, key []byte) (*Postgres, error) {
	if len(key) != crypto.KeySize {
		return nil, fmt.Errorf("store: key must be %d bytes", crypto.KeySize)
	}
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, err
	}
	config.ConnConfig.RuntimeParams["application_name"] = "password-manager"
	config.ConnConfig.RuntimeParams["statement_timeout"] = "5000"
	config.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "30000"
	config.MaxConns = 20
	if config.MinConns == 0 {
		config.MinConns = 2
	}
	config.MaxConnLifetime = time.Hour
	config.MaxConnIdleTime = time.Minute * 30

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, err
	}
	p := &Postgres{pool: pool, km: newKeyManager(key)}
	if err := p.migrate(); err != nil {
		p.pool.Close()
		return nil, err
	}
	return p, nil
}

func (p *Postgres) migrate() error {
	ctx := context.Background()
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS humans (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS agents (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			owner_kind TEXT NOT NULL DEFAULT '',
			owner_id TEXT NOT NULL DEFAULT '',
			revoked_at TIMESTAMPTZ
		)`,
		`CREATE TABLE IF NOT EXISTS items (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			name TEXT NOT NULL,
			kind TEXT NOT NULL,
			owner_kind TEXT NOT NULL,
			owner_id TEXT NOT NULL,
			uris TEXT NOT NULL,
			secret BYTEA NOT NULL,
			has_totp BOOLEAN NOT NULL DEFAULT FALSE,
			tags TEXT NOT NULL DEFAULT '[]',
			archived BOOLEAN NOT NULL DEFAULT FALSE,
			has_file BOOLEAN NOT NULL DEFAULT FALSE,
			login TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS grants (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			agent_id TEXT NOT NULL,
			item_id TEXT NOT NULL,
			level TEXT NOT NULL,
			actions TEXT NOT NULL,
			expires_at TIMESTAMPTZ,
			UNIQUE(agent_id, item_id)
		)`,
		`CREATE TABLE IF NOT EXISTS approvals (
			grant_id TEXT PRIMARY KEY,
			id TEXT NOT NULL,
			human_id TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS audit (
			id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
			at TIMESTAMPTZ NOT NULL,
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
			wrapped BYTEA NOT NULL,
			PRIMARY KEY (owner_kind, owner_id)
		)`,
		`CREATE TABLE IF NOT EXISTS item_versions (
			id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
			item_id TEXT NOT NULL,
			at TIMESTAMPTZ NOT NULL,
			secret BYTEA NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			agent_id TEXT NOT NULL,
			secret_hash BYTEA NOT NULL UNIQUE,
			expires_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_items_org_name ON items(org_id, name)`,
		`CREATE INDEX IF NOT EXISTS idx_items_org_archived_name ON items(org_id, archived, name)`,
		`CREATE INDEX IF NOT EXISTS idx_grants_item ON grants(item_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_agent_at ON audit(agent_id, at)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_item_versions_item ON item_versions(item_id, id)`,
		`CREATE INDEX IF NOT EXISTS idx_workloads_issuer ON workloads(issuer)`,
	} {
		if _, err := p.pool.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func (p *Postgres) Close() error { p.pool.Close(); return nil }

func (p *Postgres) ownerDEK(o protocol.Owner) ([]byte, error) {
	return p.km.ownerDEK(context.Background(), p, o)
}

func (p *Postgres) loadOwnerWrapped(ctx context.Context, o protocol.Owner) ([]byte, error) {
	var wrapped []byte
	err := p.pool.QueryRow(ctx, `SELECT wrapped FROM owner_keys WHERE owner_kind=$1 AND owner_id=$2`, o.Kind, o.ID).Scan(&wrapped)
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	return wrapped, err
}

func (p *Postgres) storeOwnerWrapped(ctx context.Context, o protocol.Owner, wrapped []byte) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO owner_keys(owner_kind, owner_id, wrapped) VALUES($1,$2,$3)
		ON CONFLICT(owner_kind, owner_id) DO NOTHING`, o.Kind, o.ID, wrapped)
	return err
}

func scanPostgresAgent(row pgx.Row) (protocol.Principal, error) {
	var p protocol.Principal
	p.Kind = protocol.PrincipalAgent
	var ownerKind, ownerID string
	var revoked sql.NullTime
	err := row.Scan(&p.ID, &p.OrgID, &ownerKind, &ownerID, &revoked)
	if err == pgx.ErrNoRows {
		return protocol.Principal{}, ErrNotFound
	}
	if err != nil {
		return protocol.Principal{}, err
	}
	p.Owner.Kind = protocol.OwnerKind(ownerKind)
	p.Owner.ID = ownerID
	if revoked.Valid {
		t := revoked.Time.UTC()
		p.RevokedAt = &t
	}
	return p, nil
}

func (p *Postgres) PutAgent(agent protocol.Principal) error {
	ctx := context.Background()
	var revoked *time.Time
	if agent.RevokedAt != nil {
		t := agent.RevokedAt.UTC()
		revoked = &t
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO agents(id, org_id, owner_kind, owner_id, revoked_at)
		VALUES($1,$2,$3,$4,$5)
		ON CONFLICT(id) DO UPDATE SET
			org_id=excluded.org_id, owner_kind=excluded.owner_kind, owner_id=excluded.owner_id,
			revoked_at=COALESCE(agents.revoked_at, excluded.revoked_at)`,
		agent.ID, agent.OrgID, agent.Owner.Kind, agent.Owner.ID, revoked)
	return err
}

func (p *Postgres) Agent(id string) (protocol.Principal, error) {
	return scanPostgresAgent(p.pool.QueryRow(context.Background(), `SELECT id, org_id, owner_kind, owner_id, revoked_at FROM agents WHERE id=$1`, id))
}

func (p *Postgres) ListAgents() ([]protocol.Principal, error) {
	ctx := context.Background()
	rows, err := p.pool.Query(ctx, `SELECT id, org_id, owner_kind, owner_id, revoked_at FROM agents ORDER BY id LIMIT $1`, maxListResults)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Principal
	for rows.Next() {
		ag, err := scanPostgresAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ag)
	}
	return out, rows.Err()
}

func (p *Postgres) RevokeAgent(id string, at time.Time, audit ...protocol.AuditEvent) error {
	ctx := context.Background()
	if len(audit) == 0 {
		res, err := p.pool.Exec(ctx, `UPDATE agents SET revoked_at = COALESCE(revoked_at, $1) WHERE id = $2`, at.UTC(), id)
		if err != nil {
			return err
		}
		if res.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	}

	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	res, err := tx.Exec(ctx, `UPDATE agents SET revoked_at = COALESCE(revoked_at, $1) WHERE id = $2`, at.UTC(), id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	for _, e := range audit {
		if _, err := tx.Exec(ctx, `INSERT INTO audit(at, org_id, agent_id, item_id, action, decision, reason, approval_id)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
			e.Time.UTC(), e.OrgID, e.AgentID, e.ItemID, e.Action, e.Decision, e.Reason, e.ApprovalID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (p *Postgres) PutHuman(h protocol.Principal) error {
	ctx := context.Background()
	_, err := p.pool.Exec(ctx, `INSERT INTO humans(id, org_id) VALUES($1, $2)
		ON CONFLICT(id) DO UPDATE SET org_id=excluded.org_id`, h.ID, h.OrgID)
	return err
}

func (p *Postgres) Human(id string) (protocol.Principal, error) {
	ctx := context.Background()
	var h protocol.Principal
	h.Kind = protocol.PrincipalHuman
	err := p.pool.QueryRow(ctx, `SELECT id, org_id FROM humans WHERE id=$1`, id).Scan(&h.ID, &h.OrgID)
	if err == pgx.ErrNoRows {
		return protocol.Principal{}, ErrNotFound
	}
	return h, err
}

func (p *Postgres) ListHumans() ([]protocol.Principal, error) {
	ctx := context.Background()
	rows, err := p.pool.Query(ctx, `SELECT id, org_id FROM humans ORDER BY id LIMIT $1`, maxListResults)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Principal
	for rows.Next() {
		var h protocol.Principal
		h.Kind = protocol.PrincipalHuman
		if err := rows.Scan(&h.ID, &h.OrgID); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (p *Postgres) snapshot(c pgConn, id string) error {
	ctx := context.Background()
	var blob []byte
	err := c.QueryRow(ctx, `SELECT secret FROM items WHERE id=$1`, id).Scan(&blob)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = c.Exec(ctx, `INSERT INTO item_versions(item_id, at, secret) VALUES($1,$2,$3)`,
		id, time.Now().UTC(), blob)
	return err
}

func (p *Postgres) PutItem(item protocol.Item, secret Secret) error {
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
	dek, err := p.ownerDEK(item.Owner)
	if err != nil {
		return err
	}
	blob, err := crypto.Seal(dek, secret)
	if err != nil {
		return err
	}

	ctx := context.Background()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	var existingOwner protocol.Owner
	err = tx.QueryRow(ctx, `SELECT owner_kind, owner_id FROM items WHERE id=$1`, item.ID).Scan(&existingOwner.Kind, &existingOwner.ID)
	if err == nil {
		if existingOwner != item.Owner {
			return fmt.Errorf("store: cannot change item owner")
		}
	} else if err != pgx.ErrNoRows {
		return err
	}

	if err := p.snapshot(tx, item.ID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO items(id, org_id, name, kind, owner_kind, owner_id, uris, secret, has_totp, tags, archived, has_file, login)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT(id) DO UPDATE SET
			org_id=excluded.org_id, name=excluded.name, kind=excluded.kind,
			owner_kind=excluded.owner_kind, owner_id=excluded.owner_id,
			uris=excluded.uris, secret=excluded.secret, has_totp=excluded.has_totp,
			tags=excluded.tags, archived=excluded.archived, has_file=excluded.has_file,
			login=excluded.login`,
		item.ID, item.OrgID, item.Name, item.Kind, item.Owner.Kind, item.Owner.ID,
		string(uris), blob, item.HasTOTP, string(tags), item.Archived, item.HasFile, item.Login)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func (p *Postgres) scanItem(row pgx.Row) (protocol.Item, error) {
	var item protocol.Item
	var uris, tags string
	var has, arch, hf bool
	err := row.Scan(&item.ID, &item.OrgID, &item.Name, &item.Kind, &item.Owner.Kind, &item.Owner.ID,
		&uris, &has, &tags, &arch, &hf, &item.Login)
	if err == pgx.ErrNoRows {
		return protocol.Item{}, ErrNotFound
	}
	if err != nil {
		return protocol.Item{}, err
	}
	if len(uris) > 0 {
		_ = json.Unmarshal([]byte(uris), &item.URIs)
	}
	if len(tags) > 0 {
		_ = json.Unmarshal([]byte(tags), &item.Tags)
	}
	item.HasTOTP = has
	item.Archived = arch
	item.HasFile = hf
	return item, nil
}

func (p *Postgres) Item(id string) (protocol.Item, error) {
	return p.scanItem(p.pool.QueryRow(context.Background(), `SELECT id, org_id, name, kind, owner_kind, owner_id, uris, has_totp, tags, archived, has_file, login FROM items WHERE id=$1`, id))
}

func (p *Postgres) ItemByName(orgID, name string) (protocol.Item, error) {
	return p.scanItem(p.pool.QueryRow(context.Background(), `SELECT id, org_id, name, kind, owner_kind, owner_id, uris, has_totp, tags, archived, has_file, login FROM items WHERE org_id=$1 AND name=$2`, orgID, name))
}

func (p *Postgres) ListItems() ([]protocol.Item, error) {
	ctx := context.Background()
	rows, err := p.pool.Query(ctx, `SELECT id, org_id, name, kind, owner_kind, owner_id, uris, has_totp, tags, archived, has_file, login FROM items WHERE archived=$1 ORDER BY name LIMIT $2`, false, maxListResults)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Item
	for rows.Next() {
		item, err := p.scanItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (p *Postgres) ArchiveItem(id string) error {
	ctx := context.Background()
	res, err := p.pool.Exec(ctx, `UPDATE items SET archived=$1 WHERE id=$2`, true, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) DeleteItem(id string) error {
	ctx := context.Background()
	if _, err := p.pool.Exec(ctx, `DELETE FROM item_versions WHERE item_id=$1`, id); err != nil {
		return err
	}
	if _, err := p.pool.Exec(ctx, `DELETE FROM grants WHERE item_id=$1`, id); err != nil {
		return err
	}
	res, err := p.pool.Exec(ctx, `DELETE FROM items WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) Versions(itemID string) ([]protocol.ItemVersion, error) {
	// Keep the newest maxListResults snapshots, then return them in
	// chronological order (oldest first) so callers can restore by index.
	ctx := context.Background()
	rows, err := p.pool.Query(ctx, `SELECT id, item_id, at FROM item_versions WHERE item_id=$1 ORDER BY id DESC LIMIT $2`, itemID, maxListResults)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.ItemVersion
	for rows.Next() {
		var v protocol.ItemVersion
		var at time.Time
		if err := rows.Scan(&v.ID, &v.ItemID, &at); err != nil {
			return nil, err
		}
		v.Time = at.UTC()
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func (p *Postgres) RestoreVersion(itemID string, versionID int64) error {
	ctx := context.Background()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	if err := p.snapshot(tx, itemID); err != nil {
		return err
	}
	var blob []byte
	err = tx.QueryRow(ctx, `SELECT secret FROM item_versions WHERE id=$1 AND item_id=$2`, versionID, itemID).Scan(&blob)
	if err == pgx.ErrNoRows {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE items SET secret=$1 WHERE id=$2`, blob, itemID)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func (p *Postgres) Secret(id string) (Secret, error) {
	ctx := context.Background()
	var blob []byte
	var owner protocol.Owner
	err := p.pool.QueryRow(ctx, `SELECT secret, owner_kind, owner_id FROM items WHERE id=$1`, id).Scan(&blob, &owner.Kind, &owner.ID)
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	dek, err := p.ownerDEK(owner)
	if err != nil {
		return nil, err
	}
	plain, err := crypto.Open(dek, blob)
	if err != nil {
		return nil, err
	}
	return Secret(plain), nil
}

func (p *Postgres) PutGrant(g protocol.Grant) error {
	ctx := context.Background()
	actions, err := json.Marshal(g.Actions)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO grants(id, org_id, agent_id, item_id, level, actions, expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT(agent_id, item_id) DO UPDATE SET
			id=excluded.id, org_id=excluded.org_id, level=excluded.level,
			actions=excluded.actions, expires_at=excluded.expires_at`,
		g.ID, g.OrgID, g.AgentID, g.ItemID, g.Level, string(actions), g.ExpiresAt)
	return err
}

func scanPostgresGrant(row pgx.Row) (*protocol.Grant, error) {
	var g protocol.Grant
	var actions string
	var exp sql.NullTime
	err := row.Scan(&g.ID, &g.OrgID, &g.AgentID, &g.ItemID, &g.Level, &actions, &exp)
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(actions) > 0 {
		_ = json.Unmarshal([]byte(actions), &g.Actions)
	}
	if exp.Valid {
		t := exp.Time.UTC()
		g.ExpiresAt = &t
	}
	return &g, nil
}

func (p *Postgres) Grant(id string) (*protocol.Grant, error) {
	return scanPostgresGrant(p.pool.QueryRow(context.Background(), `SELECT id, org_id, agent_id, item_id, level, actions, expires_at FROM grants WHERE id=$1`, id))
}

func (p *Postgres) GrantFor(agentID, itemID string) (*protocol.Grant, error) {
	g, err := scanPostgresGrant(p.pool.QueryRow(context.Background(), `SELECT id, org_id, agent_id, item_id, level, actions, expires_at FROM grants WHERE agent_id=$1 AND item_id=$2`, agentID, itemID))
	if err == ErrNotFound {
		return nil, nil
	}
	return g, err
}

func (p *Postgres) ListGrants() ([]protocol.Grant, error) {
	ctx := context.Background()
	rows, err := p.pool.Query(ctx, `SELECT id, org_id, agent_id, item_id, level, actions, expires_at FROM grants ORDER BY id LIMIT $1`, maxListResults)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Grant
	for rows.Next() {
		g, err := scanPostgresGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

func (p *Postgres) PutApproval(a protocol.Approval) error {
	ctx := context.Background()
	_, err := p.pool.Exec(ctx, `INSERT INTO approvals(grant_id, id, human_id, expires_at) VALUES($1,$2,$3,$4)
		ON CONFLICT(grant_id) DO UPDATE SET id=excluded.id, human_id=excluded.human_id, expires_at=excluded.expires_at`,
		a.GrantID, a.ID, a.HumanID, a.ExpiresAt.UTC())
	return err
}

func (p *Postgres) LiveApproval(grantID string, now time.Time) (*protocol.Approval, error) {
	ctx := context.Background()
	var a protocol.Approval
	var exp time.Time
	err := p.pool.QueryRow(ctx, `SELECT grant_id, id, human_id, expires_at FROM approvals WHERE grant_id=$1`, grantID).
		Scan(&a.GrantID, &a.ID, &a.HumanID, &exp)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.ExpiresAt = exp.UTC()
	if !now.Before(a.ExpiresAt) {
		return nil, nil
	}
	return &a, nil
}

func (p *Postgres) PutWorkload(w protocol.Workload) error {
	ctx := context.Background()
	_, err := p.pool.Exec(ctx, `INSERT INTO workloads(issuer, subject, agent_id, audience)
		VALUES($1,$2,$3,$4)
		ON CONFLICT(issuer, subject) DO UPDATE SET
			agent_id=excluded.agent_id, audience=excluded.audience`,
		w.Issuer, w.Subject, w.AgentID, w.Audience)
	return err
}

func (p *Postgres) Workload(issuer, subject string) (*protocol.Workload, error) {
	ctx := context.Background()
	var w protocol.Workload
	err := p.pool.QueryRow(ctx, `SELECT agent_id, issuer, subject, audience FROM workloads WHERE issuer=$1 AND subject=$2`, issuer, subject).
		Scan(&w.AgentID, &w.Issuer, &w.Subject, &w.Audience)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &w, nil
}

func (p *Postgres) WorkloadsForIssuer(issuer string) ([]protocol.Workload, error) {
	ctx := context.Background()
	rows, err := p.pool.Query(ctx, `SELECT agent_id, issuer, subject, audience FROM workloads WHERE issuer=$1 ORDER BY subject LIMIT $2`, issuer, maxListResults)
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

func (p *Postgres) PutSession(sess protocol.Session, secretHash []byte) error {
	ctx := context.Background()
	_, err := p.pool.Exec(ctx, `INSERT INTO sessions(id, org_id, agent_id, secret_hash, expires_at)
		VALUES($1,$2,$3,$4,$5)`,
		sess.ID, sess.OrgID, sess.AgentID, secretHash, sess.ExpiresAt.UTC())
	return err
}

func (p *Postgres) SessionByHash(secretHash []byte) (protocol.Session, error) {
	ctx := context.Background()
	var sess protocol.Session
	err := p.pool.QueryRow(ctx, `SELECT id, org_id, agent_id, expires_at FROM sessions WHERE secret_hash=$1`, secretHash).
		Scan(&sess.ID, &sess.OrgID, &sess.AgentID, &sess.ExpiresAt)
	if err == pgx.ErrNoRows {
		return protocol.Session{}, ErrNotFound
	}
	if err != nil {
		return protocol.Session{}, err
	}
	sess.ExpiresAt = sess.ExpiresAt.UTC()
	return sess, nil
}

func (p *Postgres) ListSessions() ([]protocol.Session, error) {
	ctx := context.Background()
	rows, err := p.pool.Query(ctx, `SELECT id, org_id, agent_id, expires_at FROM sessions ORDER BY expires_at LIMIT $1`, maxListResults)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Session
	for rows.Next() {
		var sess protocol.Session
		if err := rows.Scan(&sess.ID, &sess.OrgID, &sess.AgentID, &sess.ExpiresAt); err != nil {
			return nil, err
		}
		sess.ExpiresAt = sess.ExpiresAt.UTC()
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (p *Postgres) AppendAudit(e protocol.AuditEvent) error {
	ctx := context.Background()
	_, err := p.pool.Exec(ctx, `INSERT INTO audit(at, org_id, agent_id, item_id, action, decision, reason, approval_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		e.Time.UTC(), e.OrgID, e.AgentID, e.ItemID, e.Action, e.Decision, e.Reason, e.ApprovalID)
	return err
}

func (p *Postgres) Audit() ([]protocol.AuditEvent, error) {
	ctx := context.Background()
	rows, err := p.pool.Query(ctx, `SELECT at, org_id, agent_id, item_id, action, decision, reason, approval_id FROM audit ORDER BY id DESC LIMIT $1`, maxListResults)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rev []protocol.AuditEvent
	for rows.Next() {
		var e protocol.AuditEvent
		var at time.Time
		if err := rows.Scan(&at, &e.OrgID, &e.AgentID, &e.ItemID, &e.Action, &e.Decision, &e.Reason, &e.ApprovalID); err != nil {
			return nil, err
		}
		e.Time = at.UTC()
		rev = append(rev, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]protocol.AuditEvent, len(rev))
	for i := range rev {
		out[i] = rev[len(rev)-1-i]
	}
	return out, nil
}

var (
	_ Store       = (*Postgres)(nil)
	_ ownerSource = (*Postgres)(nil)
)
