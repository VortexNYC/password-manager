-- name: UseAuth :one
SELECT
    a.id AS agent_id,
    a.org_id AS agent_org_id,
    a.owner_kind AS agent_owner_kind,
    a.owner_id AS agent_owner_id,
    a.revoked_at AS agent_revoked_at,
    i.id AS item_id,
    i.org_id AS item_org_id,
    i.name AS item_name,
    i.kind AS item_kind,
    i.owner_kind AS item_owner_kind,
    i.owner_id AS item_owner_id,
    i.uris AS item_uris,
    i.has_totp AS item_has_totp,
    i.tags AS item_tags,
    i.archived AS item_archived,
    i.has_file AS item_has_file,
    i.login AS item_login,
    g.id AS grant_id,
    g.org_id AS grant_org_id,
    g.agent_id AS grant_agent_id,
    g.item_id AS grant_item_id,
    g.level AS grant_level,
    g.actions AS grant_actions,
    g.expires_at AS grant_expires_at,
    ap.id AS approval_id,
    ap.grant_id AS approval_grant_id,
    ap.human_id AS approval_human_id,
    ap.expires_at AS approval_expires_at
FROM (SELECT @agent_id::text AS agent_id, @item_id::text AS item_id, @now::timestamptz AS now) AS v
LEFT JOIN agents a ON a.id = v.agent_id
LEFT JOIN items i ON i.id = v.item_id
LEFT JOIN grants g ON g.agent_id = v.agent_id AND g.item_id = i.id
LEFT JOIN approvals ap ON ap.grant_id = g.id AND ap.expires_at > v.now;

-- name: UseAuthSession :one
SELECT
    s.id AS session_id,
    a.id AS agent_id,
    a.org_id AS agent_org_id,
    a.owner_kind AS agent_owner_kind,
    a.owner_id AS agent_owner_id,
    a.revoked_at AS agent_revoked_at,
    i.id AS item_id,
    i.org_id AS item_org_id,
    i.name AS item_name,
    i.kind AS item_kind,
    i.owner_kind AS item_owner_kind,
    i.owner_id AS item_owner_id,
    i.uris AS item_uris,
    i.has_totp AS item_has_totp,
    i.tags AS item_tags,
    i.archived AS item_archived,
    i.has_file AS item_has_file,
    i.login AS item_login,
    g.id AS grant_id,
    g.org_id AS grant_org_id,
    g.agent_id AS grant_agent_id,
    g.item_id AS grant_item_id,
    g.level AS grant_level,
    g.actions AS grant_actions,
    g.expires_at AS grant_expires_at,
    ap.id AS approval_id,
    ap.grant_id AS approval_grant_id,
    ap.human_id AS approval_human_id,
    ap.expires_at AS approval_expires_at
FROM (SELECT @session_hash::bytea AS session_hash, @item_id::text AS item_id, @now::timestamptz AS now) AS v
LEFT JOIN sessions s ON s.secret_hash = v.session_hash AND s.expires_at > v.now AND s.revoked_at IS NULL AND (s.max_uses = 0 OR s.uses < s.max_uses)
LEFT JOIN agents a ON a.id = s.agent_id
LEFT JOIN items i ON i.id = v.item_id
LEFT JOIN grants g ON g.agent_id = s.agent_id AND g.item_id = i.id
LEFT JOIN approvals ap ON ap.grant_id = g.id AND ap.expires_at > v.now;

-- name: ConsumeSession :one
UPDATE sessions s
SET uses = uses + 1
FROM agents a
WHERE s.secret_hash = @session_hash::bytea
  AND s.agent_id = a.id
  AND a.revoked_at IS NULL
  AND s.expires_at > @now::timestamptz
  AND s.revoked_at IS NULL
  AND (s.max_uses = 0 OR s.uses < s.max_uses)
RETURNING a.id AS agent_id, a.org_id AS agent_org_id, a.owner_kind AS agent_owner_kind, a.owner_id AS agent_owner_id, a.revoked_at AS agent_revoked_at;

-- name: PutSession :exec
INSERT INTO sessions(id, org_id, agent_id, secret_hash, expires_at, created_at, revoked_at, renewed_at, ttl, max_ttl, max_uses, uses)
VALUES(@id::text, @org_id::text, @agent_id::text, @secret_hash::bytea, @expires_at::timestamptz, @created_at::timestamptz, sqlc.narg(revoked_at), sqlc.narg(renewed_at), @ttl::bigint, @max_ttl::bigint, @max_uses::integer, @uses::integer)
ON CONFLICT(id) DO UPDATE SET
    org_id=excluded.org_id,
    agent_id=excluded.agent_id,
    secret_hash=excluded.secret_hash,
    expires_at=excluded.expires_at,
    created_at=excluded.created_at,
    revoked_at=excluded.revoked_at,
    renewed_at=excluded.renewed_at,
    ttl=excluded.ttl,
    max_ttl=excluded.max_ttl,
    max_uses=excluded.max_uses,
    uses=excluded.uses;

-- name: SessionByHash :one
SELECT id, org_id, agent_id, secret_hash, expires_at, created_at, revoked_at, renewed_at, ttl, max_ttl, max_uses, uses
FROM sessions WHERE secret_hash = @secret_hash::bytea;

-- name: SessionByID :one
SELECT id, org_id, agent_id, secret_hash, expires_at, created_at, revoked_at, renewed_at, ttl, max_ttl, max_uses, uses
FROM sessions WHERE id = @id::text;

-- name: ListSessions :many
SELECT id, org_id, agent_id, secret_hash, expires_at, created_at, revoked_at, renewed_at, ttl, max_ttl, max_uses, uses
FROM sessions ORDER BY expires_at LIMIT @max_results::bigint;

-- name: RevokeSession :execrows
UPDATE sessions SET revoked_at = COALESCE(revoked_at, @at::timestamptz) WHERE id = @id::text;

-- name: RenewSession :exec
UPDATE sessions SET expires_at = @expires_at::timestamptz, renewed_at = @renewed_at::timestamptz WHERE id = @id::text;

-- name: ItemOwner :one
SELECT owner_kind, owner_id FROM items WHERE id = @id::text;

-- name: SnapshotItem :exec
INSERT INTO item_versions(item_id, at, secret)
SELECT @item_id::text, @at::timestamptz, secret FROM items WHERE id = @item_id::text;

-- name: PutItem :exec
INSERT INTO items(id, org_id, name, kind, owner_kind, owner_id, uris, secret, has_totp, tags, archived, has_file, login)
VALUES(@id::text, @org_id::text, @name::text, @kind::text, @owner_kind::text, @owner_id::text, @uris::text, @secret::bytea, @has_totp::bool, @tags::text, @archived::bool, @has_file::bool, @login::text)
ON CONFLICT(id) DO UPDATE SET
    org_id=excluded.org_id, name=excluded.name, kind=excluded.kind,
    owner_kind=excluded.owner_kind, owner_id=excluded.owner_id,
    uris=excluded.uris, secret=excluded.secret, has_totp=excluded.has_totp,
    tags=excluded.tags, archived=excluded.archived, has_file=excluded.has_file,
    login=excluded.login;

-- name: ItemByID :one
SELECT id, org_id, name, kind, owner_kind, owner_id, uris, has_totp, tags, archived, has_file, login
FROM items WHERE id = @id::text;

-- name: ItemByName :one
SELECT id, org_id, name, kind, owner_kind, owner_id, uris, has_totp, tags, archived, has_file, login
FROM items WHERE org_id = @org_id::text AND name = @name::text;

-- name: ListItems :many
SELECT id, org_id, name, kind, owner_kind, owner_id, uris, has_totp, tags, archived, has_file, login
FROM items WHERE archived = FALSE ORDER BY name LIMIT @max_results::bigint;

-- name: ArchiveItem :execrows
UPDATE items SET archived = TRUE WHERE id = @id::text;

-- name: DeleteItemVersions :exec
DELETE FROM item_versions WHERE item_id = @item_id::text;

-- name: DeleteItemGrants :exec
DELETE FROM grants WHERE item_id = @item_id::text;

-- name: DeleteItem :execrows
DELETE FROM items WHERE id = @id::text;

-- name: ItemVersions :many
SELECT id, item_id, at FROM item_versions WHERE item_id = @item_id::text ORDER BY id DESC LIMIT @max_results::bigint;

-- name: ItemVersionSecret :one
SELECT secret FROM item_versions WHERE id = @id::bigint AND item_id = @item_id::text;

-- name: RestoreItemSecret :exec
UPDATE items SET secret = @secret::bytea WHERE id = @id::text;

-- name: ItemSecretOwner :one
SELECT secret, owner_kind, owner_id FROM items WHERE id = @id::text;
