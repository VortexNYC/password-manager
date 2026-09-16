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
