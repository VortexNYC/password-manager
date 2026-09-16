package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/veilnyc/password-manager/internal/crypto"
	"github.com/veilnyc/password-manager/internal/protocol"
	"github.com/veilnyc/password-manager/internal/store/sqlc"
)

// Postgres is a pgx-backed Store for the origin. Secrets are encrypted with
// per-owner data keys before they are written, same as the SQLite store.
type Postgres struct {
	pool *pgxpool.Pool
	km   *keyManager
	sqlc *sqlc.Queries
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
	p := &Postgres{pool: pool, km: newKeyManager(key), sqlc: sqlc.New(pool)}
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
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			revoked_at TIMESTAMPTZ,
			renewed_at TIMESTAMPTZ,
			ttl BIGINT NOT NULL,
			max_ttl BIGINT NOT NULL,
			max_uses INTEGER NOT NULL,
			uses INTEGER NOT NULL
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
	for _, q := range []string{
		`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01T00:00:00Z'`,
		`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ`,
		`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS renewed_at TIMESTAMPTZ`,
		`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ttl BIGINT NOT NULL DEFAULT 0`,
		`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS max_ttl BIGINT NOT NULL DEFAULT 0`,
		`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS max_uses INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS uses INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := p.pool.Exec(ctx, q); err != nil {
			return err
		}
	}
	// Legacy rows predate the lifecycle columns. Give them usable
	// created_at/ttl/max_ttl so RenewSession can extend them.
	if _, err := p.pool.Exec(ctx, `UPDATE sessions SET created_at = expires_at WHERE created_at = '1970-01-01T00:00:00Z'`); err != nil {
		return err
	}
	if _, err := p.pool.Exec(ctx, `UPDATE sessions SET ttl = 900 WHERE ttl = 0`); err != nil {
		return err
	}
	if _, err := p.pool.Exec(ctx, `UPDATE sessions SET max_ttl = 3600 WHERE max_ttl = 0`); err != nil {
		return err
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

func (p *Postgres) AppendAudit(e protocol.AuditEvent) error {
	return p.AppendAudits([]protocol.AuditEvent{e})
}

func (p *Postgres) AppendAudits(events []protocol.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	_, err := p.pool.CopyFrom(context.Background(), pgx.Identifier{"audit"}, []string{
		"at", "org_id", "agent_id", "item_id", "action", "decision", "reason", "approval_id",
	}, &auditCopySource{events: events})
	return err
}

type auditCopySource struct {
	events []protocol.AuditEvent
	idx    int
}

func (s *auditCopySource) Next() bool {
	return s.idx < len(s.events)
}

func (s *auditCopySource) Values() ([]interface{}, error) {
	e := s.events[s.idx]
	s.idx++
	return []interface{}{e.Time.UTC(), e.OrgID, e.AgentID, e.ItemID, e.Action, e.Decision, e.Reason, e.ApprovalID}, nil
}

func (s *auditCopySource) Err() error {
	return nil
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
