package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/veilnyc/password-manager/internal/crypto"
	"github.com/veilnyc/password-manager/internal/protocol"
	"github.com/veilnyc/password-manager/internal/store/sqlc"
)

func useAuthSessionToUseAuthRow(row sqlc.UseAuthSessionRow) sqlc.UseAuthRow {
	return sqlc.UseAuthRow{
		AgentID:           row.AgentID,
		AgentOrgID:        row.AgentOrgID,
		AgentOwnerKind:    row.AgentOwnerKind,
		AgentOwnerID:      row.AgentOwnerID,
		AgentRevokedAt:    row.AgentRevokedAt,
		ItemID:            row.ItemID,
		ItemOrgID:         row.ItemOrgID,
		ItemName:          row.ItemName,
		ItemKind:          row.ItemKind,
		ItemOwnerKind:     row.ItemOwnerKind,
		ItemOwnerID:       row.ItemOwnerID,
		ItemUris:          row.ItemUris,
		ItemHasTotp:       row.ItemHasTotp,
		ItemTags:          row.ItemTags,
		ItemArchived:      row.ItemArchived,
		ItemHasFile:       row.ItemHasFile,
		ItemLogin:         row.ItemLogin,
		GrantID:           row.GrantID,
		GrantOrgID:        row.GrantOrgID,
		GrantAgentID:      row.GrantAgentID,
		GrantItemID:       row.GrantItemID,
		GrantLevel:        row.GrantLevel,
		GrantActions:      row.GrantActions,
		GrantExpiresAt:    row.GrantExpiresAt,
		ApprovalID:        row.ApprovalID,
		ApprovalGrantID:   row.ApprovalGrantID,
		ApprovalHumanID:   row.ApprovalHumanID,
		ApprovalExpiresAt: row.ApprovalExpiresAt,
	}
}

func useAuthFromSqlcRow(r *sqlc.UseAuthRow) (UseAuth, error) {
	var out UseAuth
	if r.AgentID.Valid && r.AgentID.String != "" {
		out.Agent = protocol.Principal{Kind: protocol.PrincipalAgent, ID: r.AgentID.String, OrgID: r.AgentOrgID.String}
		out.Agent.Owner.Kind = protocol.OwnerKind(r.AgentOwnerKind.String)
		out.Agent.Owner.ID = r.AgentOwnerID.String
		if r.AgentRevokedAt.Valid {
			t := r.AgentRevokedAt.Time.UTC()
			out.Agent.RevokedAt = &t
		}
	}
	if r.ItemID.Valid && r.ItemID.String != "" {
		out.Item = protocol.Item{ID: r.ItemID.String, OrgID: r.ItemOrgID.String, Name: r.ItemName.String, Kind: protocol.ItemKind(r.ItemKind.String)}
		out.Item.Owner.Kind = protocol.OwnerKind(r.ItemOwnerKind.String)
		out.Item.Owner.ID = r.ItemOwnerID.String
		if r.ItemUris.Valid && r.ItemUris.String != "" {
			_ = json.Unmarshal([]byte(r.ItemUris.String), &out.Item.URIs)
		}
		if r.ItemTags.Valid && r.ItemTags.String != "" {
			_ = json.Unmarshal([]byte(r.ItemTags.String), &out.Item.Tags)
		}
		out.Item.HasTOTP = r.ItemHasTotp.Bool
		out.Item.Archived = r.ItemArchived.Bool
		out.Item.HasFile = r.ItemHasFile.Bool
		out.Item.Login = r.ItemLogin.String
	}
	if r.GrantID.Valid && r.GrantID.String != "" {
		g := &protocol.Grant{ID: r.GrantID.String, OrgID: r.GrantOrgID.String, AgentID: r.GrantAgentID.String, ItemID: r.GrantItemID.String, Level: protocol.GrantLevel(r.GrantLevel.String)}
		if r.GrantActions.Valid && r.GrantActions.String != "" {
			_ = json.Unmarshal([]byte(r.GrantActions.String), &g.Actions)
		}
		if r.GrantExpiresAt.Valid {
			t := r.GrantExpiresAt.Time.UTC()
			g.ExpiresAt = &t
		}
		out.Grant = g
	}
	if r.ApprovalID.Valid && r.ApprovalID.String != "" {
		if r.ApprovalExpiresAt.Valid {
			out.Approval = &protocol.Approval{ID: r.ApprovalID.String, GrantID: r.ApprovalGrantID.String, HumanID: r.ApprovalHumanID.String, ExpiresAt: r.ApprovalExpiresAt.Time.UTC()}
		}
	}
	return out, nil
}

func (p *Postgres) UseAuth(agentID, itemID string, now time.Time) (UseAuth, error) {
	ctx := context.Background()
	row, err := p.sqlc.UseAuth(ctx, sqlc.UseAuthParams{
		AgentID: agentID,
		ItemID:  itemID,
		Now:     now.UTC(),
	})
	if err != nil {
		return UseAuth{}, err
	}
	return useAuthFromSqlcRow(&row)
}

func (p *Postgres) UseAuthSession(sessionHash []byte, itemID string, now time.Time) (UseAuth, error) {
	ctx := context.Background()
	row, err := p.sqlc.UseAuthSession(ctx, sqlc.UseAuthSessionParams{
		SessionHash: sessionHash,
		ItemID:      itemID,
		Now:         now.UTC(),
	})
	if err != nil {
		return UseAuth{}, err
	}
	if !row.SessionID.Valid || row.SessionID.String == "" || !row.AgentID.Valid || row.AgentID.String == "" {
		return UseAuth{}, ErrNotFound
	}
	r := useAuthSessionToUseAuthRow(row)
	return useAuthFromSqlcRow(&r)
}

func (p *Postgres) ConsumeSession(sessionHash []byte, now time.Time) (protocol.Principal, error) {
	ctx := context.Background()
	row, err := p.sqlc.ConsumeSession(ctx, sqlc.ConsumeSessionParams{
		SessionHash: sessionHash,
		Now:         now.UTC(),
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return protocol.Principal{}, ErrNotFound
		}
		return protocol.Principal{}, err
	}
	a := protocol.Principal{
		Kind:  protocol.PrincipalAgent,
		ID:    row.AgentID,
		OrgID: row.AgentOrgID,
		Owner: protocol.Owner{
			Kind: protocol.OwnerKind(row.AgentOwnerKind),
			ID:   row.AgentOwnerID,
		},
	}
	if row.AgentRevokedAt.Valid {
		t := row.AgentRevokedAt.Time.UTC()
		a.RevokedAt = &t
	}
	return a, nil
}

func sessionFromSqlc(s *sqlc.Session) protocol.Session {
	sess := protocol.Session{
		ID:        s.ID,
		OrgID:     s.OrgID,
		AgentID:   s.AgentID,
		ExpiresAt: s.ExpiresAt.UTC(),
		CreatedAt: s.CreatedAt.UTC(),
		TTL:       s.Ttl,
		MaxTTL:    s.MaxTtl,
		MaxUses:   int(s.MaxUses),
		Uses:      int(s.Uses),
	}
	if s.RevokedAt.Valid {
		t := s.RevokedAt.Time.UTC()
		sess.RevokedAt = &t
	}
	if s.RenewedAt.Valid {
		t := s.RenewedAt.Time.UTC()
		sess.RenewedAt = &t
	}
	return sess
}

func nullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t.UTC(), Valid: true}
}

func (p *Postgres) PutSession(sess protocol.Session, secretHash []byte) error {
	ctx := context.Background()
	return p.sqlc.PutSession(ctx, sqlc.PutSessionParams{
		ID:         sess.ID,
		OrgID:      sess.OrgID,
		AgentID:    sess.AgentID,
		SecretHash: secretHash,
		ExpiresAt:  sess.ExpiresAt.UTC(),
		CreatedAt:  sess.CreatedAt.UTC(),
		RevokedAt:  nullTime(sess.RevokedAt),
		RenewedAt:  nullTime(sess.RenewedAt),
		Ttl:        sess.TTL,
		MaxTtl:     sess.MaxTTL,
		MaxUses:    int32(sess.MaxUses),
		Uses:       int32(sess.Uses),
	})
}

func (p *Postgres) SessionByHash(secretHash []byte) (protocol.Session, error) {
	ctx := context.Background()
	s, err := p.sqlc.SessionByHash(ctx, secretHash)
	if err == pgx.ErrNoRows {
		return protocol.Session{}, ErrNotFound
	}
	if err != nil {
		return protocol.Session{}, err
	}
	return sessionFromSqlc(&s), nil
}

func (p *Postgres) SessionByID(id string) (protocol.Session, error) {
	ctx := context.Background()
	s, err := p.sqlc.SessionByID(ctx, id)
	if err == pgx.ErrNoRows {
		return protocol.Session{}, ErrNotFound
	}
	if err != nil {
		return protocol.Session{}, err
	}
	return sessionFromSqlc(&s), nil
}

func (p *Postgres) ListSessions() ([]protocol.Session, error) {
	ctx := context.Background()
	rows, err := p.sqlc.ListSessions(ctx, maxListResults)
	if err != nil {
		return nil, err
	}
	out := make([]protocol.Session, 0, len(rows))
	for i := range rows {
		out = append(out, sessionFromSqlc(&rows[i]))
	}
	return out, nil
}

func (p *Postgres) RevokeSession(id string, at time.Time) error {
	ctx := context.Background()
	n, err := p.sqlc.RevokeSession(ctx, sqlc.RevokeSessionParams{At: at.UTC(), ID: id})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) RenewSession(id string, at time.Time) (protocol.Session, error) {
	ctx := context.Background()
	sess, err := p.SessionByID(id)
	if err != nil {
		return protocol.Session{}, err
	}
	if sess.RevokedAt != nil {
		return protocol.Session{}, ErrSessionRevoked
	}
	if !sess.ExpiresAt.After(at) {
		return protocol.Session{}, ErrSessionExpired
	}
	maxExpires := sess.CreatedAt.Add(time.Duration(sess.MaxTTL) * time.Second)
	newExpires := sess.ExpiresAt.Add(time.Duration(sess.TTL) * time.Second)
	if newExpires.After(maxExpires) {
		newExpires = maxExpires
	}
	if !newExpires.After(sess.ExpiresAt) {
		newExpires = sess.ExpiresAt
	}
	rn := at.UTC()
	sess.ExpiresAt = newExpires.UTC()
	sess.RenewedAt = &rn
	err = p.sqlc.RenewSession(ctx, sqlc.RenewSessionParams{
		ExpiresAt: sess.ExpiresAt.UTC(),
		RenewedAt: *sess.RenewedAt,
		ID:        id,
	})
	if err != nil {
		return protocol.Session{}, err
	}
	return sess, nil
}

func itemByNameToRow(r sqlc.ItemByNameRow) sqlc.ItemByIDRow {
	return sqlc.ItemByIDRow{
		ID: r.ID, OrgID: r.OrgID, Name: r.Name, Kind: r.Kind,
		OwnerKind: r.OwnerKind, OwnerID: r.OwnerID, Uris: r.Uris,
		HasTotp: r.HasTotp, Tags: r.Tags, Archived: r.Archived,
		HasFile: r.HasFile, Login: r.Login,
	}
}

func listItemsToRow(r sqlc.ListItemsRow) sqlc.ItemByIDRow {
	return sqlc.ItemByIDRow{
		ID: r.ID, OrgID: r.OrgID, Name: r.Name, Kind: r.Kind,
		OwnerKind: r.OwnerKind, OwnerID: r.OwnerID, Uris: r.Uris,
		HasTotp: r.HasTotp, Tags: r.Tags, Archived: r.Archived,
		HasFile: r.HasFile, Login: r.Login,
	}
}

func itemFromSqlc(r *sqlc.ItemByIDRow) protocol.Item {
	item := protocol.Item{
		ID:   r.ID,
		OrgID: r.OrgID,
		Name:  r.Name,
		Kind:  protocol.ItemKind(r.Kind),
		Owner: protocol.Owner{Kind: protocol.OwnerKind(r.OwnerKind), ID: r.OwnerID},
	}
	if len(r.Uris) > 0 {
		_ = json.Unmarshal([]byte(r.Uris), &item.URIs)
	}
	if len(r.Tags) > 0 {
		_ = json.Unmarshal([]byte(r.Tags), &item.Tags)
	}
	item.HasTOTP = r.HasTotp
	item.Archived = r.Archived
	item.HasFile = r.HasFile
	item.Login = r.Login
	return item
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
	qtx := p.sqlc.WithTx(tx)

	owner, err := qtx.ItemOwner(ctx, item.ID)
	if err == nil {
		if owner.OwnerKind != string(item.Owner.Kind) || owner.OwnerID != item.Owner.ID {
			return fmt.Errorf("store: cannot change item owner")
		}
	} else if err != pgx.ErrNoRows {
		return err
	}

	if err := qtx.SnapshotItem(ctx, sqlc.SnapshotItemParams{ItemID: item.ID, At: time.Now().UTC()}); err != nil {
		return err
	}
	err = qtx.PutItem(ctx, sqlc.PutItemParams{
		ID: item.ID, OrgID: item.OrgID, Name: item.Name, Kind: string(item.Kind),
		OwnerKind: string(item.Owner.Kind), OwnerID: item.Owner.ID,
		Uris: string(uris), Secret: blob, HasTotp: item.HasTOTP,
		Tags: string(tags), Archived: item.Archived, HasFile: item.HasFile,
		Login: item.Login,
	})
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func (p *Postgres) Item(id string) (protocol.Item, error) {
	r, err := p.sqlc.ItemByID(context.Background(), id)
	if err == pgx.ErrNoRows {
		return protocol.Item{}, ErrNotFound
	}
	if err != nil {
		return protocol.Item{}, err
	}
	return itemFromSqlc(&r), nil
}

func (p *Postgres) ItemByName(orgID, name string) (protocol.Item, error) {
	r, err := p.sqlc.ItemByName(context.Background(), sqlc.ItemByNameParams{OrgID: orgID, Name: name})
	if err == pgx.ErrNoRows {
		return protocol.Item{}, ErrNotFound
	}
	if err != nil {
		return protocol.Item{}, err
	}
	row := itemByNameToRow(r)
	return itemFromSqlc(&row), nil
}

func (p *Postgres) ListItems() ([]protocol.Item, error) {
	rows, err := p.sqlc.ListItems(context.Background(), maxListResults)
	if err != nil {
		return nil, err
	}
	out := make([]protocol.Item, 0, len(rows))
	for i := range rows {
		r := listItemsToRow(rows[i])
		out = append(out, itemFromSqlc(&r))
	}
	return out, nil
}

func (p *Postgres) ArchiveItem(id string) error {
	n, err := p.sqlc.ArchiveItem(context.Background(), id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) DeleteItem(id string) error {
	ctx := context.Background()
	if err := p.sqlc.DeleteItemVersions(ctx, id); err != nil {
		return err
	}
	if err := p.sqlc.DeleteItemGrants(ctx, id); err != nil {
		return err
	}
	n, err := p.sqlc.DeleteItem(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) Versions(itemID string) ([]protocol.ItemVersion, error) {
	rows, err := p.sqlc.ItemVersions(context.Background(), sqlc.ItemVersionsParams{ItemID: itemID, MaxResults: maxListResults})
	if err != nil {
		return nil, err
	}
	out := make([]protocol.ItemVersion, 0, len(rows))
	for i := range rows {
		out = append(out, protocol.ItemVersion{ID: rows[i].ID, ItemID: rows[i].ItemID, Time: rows[i].At.UTC()})
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
	qtx := p.sqlc.WithTx(tx)

	if err := qtx.SnapshotItem(ctx, sqlc.SnapshotItemParams{ItemID: itemID, At: time.Now().UTC()}); err != nil {
		return err
	}
	blob, err := qtx.ItemVersionSecret(ctx, sqlc.ItemVersionSecretParams{ID: versionID, ItemID: itemID})
	if err == pgx.ErrNoRows {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := qtx.RestoreItemSecret(ctx, sqlc.RestoreItemSecretParams{Secret: blob, ID: itemID}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func (p *Postgres) Secret(id string) (Secret, error) {
	r, err := p.sqlc.ItemSecretOwner(context.Background(), id)
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	dek, err := p.ownerDEK(protocol.Owner{Kind: protocol.OwnerKind(r.OwnerKind), ID: r.OwnerID})
	if err != nil {
		return nil, err
	}
	plain, err := crypto.Open(dek, r.Secret)
	if err != nil {
		return nil, err
	}
	return Secret(plain), nil
}

func grantFromSqlc(r *sqlc.Grant) *protocol.Grant {
	g := &protocol.Grant{
		ID: r.ID, OrgID: r.OrgID, AgentID: r.AgentID, ItemID: r.ItemID,
		Level: protocol.GrantLevel(r.Level),
	}
	if len(r.Actions) > 0 {
		_ = json.Unmarshal([]byte(r.Actions), &g.Actions)
	}
	if r.ExpiresAt.Valid {
		t := r.ExpiresAt.Time.UTC()
		g.ExpiresAt = &t
	}
	return g
}

func (p *Postgres) PutGrant(g protocol.Grant) error {
	actions, err := json.Marshal(g.Actions)
	if err != nil {
		return err
	}
	return p.sqlc.PutGrant(context.Background(), sqlc.PutGrantParams{
		ID: g.ID, OrgID: g.OrgID, AgentID: g.AgentID, ItemID: g.ItemID,
		Level: string(g.Level), Actions: string(actions), ExpiresAt: nullTime(g.ExpiresAt),
	})
}

func (p *Postgres) Grant(id string) (*protocol.Grant, error) {
	r, err := p.sqlc.GrantByID(context.Background(), id)
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return grantFromSqlc(&r), nil
}

func (p *Postgres) GrantFor(agentID, itemID string) (*protocol.Grant, error) {
	r, err := p.sqlc.GrantFor(context.Background(), sqlc.GrantForParams{AgentID: agentID, ItemID: itemID})
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return grantFromSqlc(&r), nil
}

func (p *Postgres) ListGrants() ([]protocol.Grant, error) {
	rows, err := p.sqlc.ListGrants(context.Background(), maxListResults)
	if err != nil {
		return nil, err
	}
	out := make([]protocol.Grant, 0, len(rows))
	for i := range rows {
		out = append(out, *grantFromSqlc(&rows[i]))
	}
	return out, nil
}

func (p *Postgres) PutApproval(a protocol.Approval) error {
	return p.sqlc.PutApproval(context.Background(), sqlc.PutApprovalParams{
		GrantID: a.GrantID, ID: a.ID, HumanID: a.HumanID, ExpiresAt: a.ExpiresAt.UTC(),
	})
}

func (p *Postgres) LiveApproval(grantID string, now time.Time) (*protocol.Approval, error) {
	r, err := p.sqlc.ApprovalByGrant(context.Background(), grantID)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a := protocol.Approval{GrantID: r.GrantID, ID: r.ID, HumanID: r.HumanID, ExpiresAt: r.ExpiresAt.UTC()}
	if !now.Before(a.ExpiresAt) {
		return nil, nil
	}
	return &a, nil
}
