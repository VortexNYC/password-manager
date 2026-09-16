package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/veilnyc/password-manager/internal/protocol"
	"github.com/veilnyc/password-manager/internal/store/sqlc"
)

func useAuthRowFromSqlc(row sqlc.UseAuthRow) useAuthRow {
	return useAuthRow{
		aID:        sql.NullString{String: row.AgentID.String, Valid: row.AgentID.Valid},
		aOrgID:     sql.NullString{String: row.AgentOrgID.String, Valid: row.AgentOrgID.Valid},
		aOwnerKind: sql.NullString{String: row.AgentOwnerKind.String, Valid: row.AgentOwnerKind.Valid},
		aOwnerID:   sql.NullString{String: row.AgentOwnerID.String, Valid: row.AgentOwnerID.Valid},
		aRevoked:   sql.NullTime{Time: row.AgentRevokedAt.Time, Valid: row.AgentRevokedAt.Valid},
		iID:        sql.NullString{String: row.ItemID.String, Valid: row.ItemID.Valid},
		iOrgID:     sql.NullString{String: row.ItemOrgID.String, Valid: row.ItemOrgID.Valid},
		iName:      sql.NullString{String: row.ItemName.String, Valid: row.ItemName.Valid},
		iKind:      sql.NullString{String: row.ItemKind.String, Valid: row.ItemKind.Valid},
		iOwnerKind: sql.NullString{String: row.ItemOwnerKind.String, Valid: row.ItemOwnerKind.Valid},
		iOwnerID:   sql.NullString{String: row.ItemOwnerID.String, Valid: row.ItemOwnerID.Valid},
		iURIs:      sql.NullString{String: row.ItemUris.String, Valid: row.ItemUris.Valid},
		iHasTOTP:   sql.NullBool{Bool: row.ItemHasTotp.Bool, Valid: row.ItemHasTotp.Valid},
		iTags:      sql.NullString{String: row.ItemTags.String, Valid: row.ItemTags.Valid},
		iArchived:  sql.NullBool{Bool: row.ItemArchived.Bool, Valid: row.ItemArchived.Valid},
		iHasFile:   sql.NullBool{Bool: row.ItemHasFile.Bool, Valid: row.ItemHasFile.Valid},
		iLogin:     sql.NullString{String: row.ItemLogin.String, Valid: row.ItemLogin.Valid},
		gID:        sql.NullString{String: row.GrantID.String, Valid: row.GrantID.Valid},
		gOrgID:     sql.NullString{String: row.GrantOrgID.String, Valid: row.GrantOrgID.Valid},
		gAgentID:   sql.NullString{String: row.GrantAgentID.String, Valid: row.GrantAgentID.Valid},
		gItemID:    sql.NullString{String: row.GrantItemID.String, Valid: row.GrantItemID.Valid},
		gLevel:     sql.NullString{String: row.GrantLevel.String, Valid: row.GrantLevel.Valid},
		gActions:   sql.NullString{String: row.GrantActions.String, Valid: row.GrantActions.Valid},
		gExpires:   sql.NullTime{Time: row.GrantExpiresAt.Time, Valid: row.GrantExpiresAt.Valid},
		apID:       sql.NullString{String: row.ApprovalID.String, Valid: row.ApprovalID.Valid},
		apGrantID:  sql.NullString{String: row.ApprovalGrantID.String, Valid: row.ApprovalGrantID.Valid},
		apHumanID:  sql.NullString{String: row.ApprovalHumanID.String, Valid: row.ApprovalHumanID.Valid},
		apExpires:  sql.NullTime{Time: row.ApprovalExpiresAt.Time, Valid: row.ApprovalExpiresAt.Valid},
	}
}

func useAuthRowFromSqlcSession(row sqlc.UseAuthSessionRow) useAuthRow {
	return useAuthRow{
		aID:        sql.NullString{String: row.AgentID.String, Valid: row.AgentID.Valid},
		aOrgID:     sql.NullString{String: row.AgentOrgID.String, Valid: row.AgentOrgID.Valid},
		aOwnerKind: sql.NullString{String: row.AgentOwnerKind.String, Valid: row.AgentOwnerKind.Valid},
		aOwnerID:   sql.NullString{String: row.AgentOwnerID.String, Valid: row.AgentOwnerID.Valid},
		aRevoked:   sql.NullTime{Time: row.AgentRevokedAt.Time, Valid: row.AgentRevokedAt.Valid},
		iID:        sql.NullString{String: row.ItemID.String, Valid: row.ItemID.Valid},
		iOrgID:     sql.NullString{String: row.ItemOrgID.String, Valid: row.ItemOrgID.Valid},
		iName:      sql.NullString{String: row.ItemName.String, Valid: row.ItemName.Valid},
		iKind:      sql.NullString{String: row.ItemKind.String, Valid: row.ItemKind.Valid},
		iOwnerKind: sql.NullString{String: row.ItemOwnerKind.String, Valid: row.ItemOwnerKind.Valid},
		iOwnerID:   sql.NullString{String: row.ItemOwnerID.String, Valid: row.ItemOwnerID.Valid},
		iURIs:      sql.NullString{String: row.ItemUris.String, Valid: row.ItemUris.Valid},
		iHasTOTP:   sql.NullBool{Bool: row.ItemHasTotp.Bool, Valid: row.ItemHasTotp.Valid},
		iTags:      sql.NullString{String: row.ItemTags.String, Valid: row.ItemTags.Valid},
		iArchived:  sql.NullBool{Bool: row.ItemArchived.Bool, Valid: row.ItemArchived.Valid},
		iHasFile:   sql.NullBool{Bool: row.ItemHasFile.Bool, Valid: row.ItemHasFile.Valid},
		iLogin:     sql.NullString{String: row.ItemLogin.String, Valid: row.ItemLogin.Valid},
		gID:        sql.NullString{String: row.GrantID.String, Valid: row.GrantID.Valid},
		gOrgID:     sql.NullString{String: row.GrantOrgID.String, Valid: row.GrantOrgID.Valid},
		gAgentID:   sql.NullString{String: row.GrantAgentID.String, Valid: row.GrantAgentID.Valid},
		gItemID:    sql.NullString{String: row.GrantItemID.String, Valid: row.GrantItemID.Valid},
		gLevel:     sql.NullString{String: row.GrantLevel.String, Valid: row.GrantLevel.Valid},
		gActions:   sql.NullString{String: row.GrantActions.String, Valid: row.GrantActions.Valid},
		gExpires:   sql.NullTime{Time: row.GrantExpiresAt.Time, Valid: row.GrantExpiresAt.Valid},
		apID:       sql.NullString{String: row.ApprovalID.String, Valid: row.ApprovalID.Valid},
		apGrantID:  sql.NullString{String: row.ApprovalGrantID.String, Valid: row.ApprovalGrantID.Valid},
		apHumanID:  sql.NullString{String: row.ApprovalHumanID.String, Valid: row.ApprovalHumanID.Valid},
		apExpires:  sql.NullTime{Time: row.ApprovalExpiresAt.Time, Valid: row.ApprovalExpiresAt.Valid},
	}
}

func (p *Postgres) UseAuth(agentID, itemID string, now time.Time) (UseAuth, error) {
	ctx := context.Background()
	row, err := p.sqlc.UseAuth(ctx, sqlc.UseAuthParams{
		AgentID: agentID,
		ItemID:  itemID,
		Now:     pgtype.Timestamptz{Time: now.UTC(), Valid: true},
	})
	if err != nil {
		return UseAuth{}, err
	}
	r := useAuthRowFromSqlc(row)
	return useAuthFromRow(&r)
}

func (p *Postgres) UseAuthSession(sessionHash []byte, itemID string, now time.Time) (UseAuth, error) {
	ctx := context.Background()
	row, err := p.sqlc.UseAuthSession(ctx, sqlc.UseAuthSessionParams{
		SessionHash: sessionHash,
		ItemID:      itemID,
		Now:         pgtype.Timestamptz{Time: now.UTC(), Valid: true},
	})
	if err != nil {
		return UseAuth{}, err
	}
	if !row.SessionID.Valid || row.SessionID.String == "" || !row.AgentID.Valid || row.AgentID.String == "" {
		return UseAuth{}, ErrNotFound
	}
	r := useAuthRowFromSqlcSession(row)
	return useAuthFromRow(&r)
}

func (p *Postgres) ConsumeSession(sessionHash []byte, now time.Time) (protocol.Principal, error) {
	ctx := context.Background()
	row, err := p.sqlc.ConsumeSession(ctx, sqlc.ConsumeSessionParams{
		SessionHash: sessionHash,
		Now:         pgtype.Timestamptz{Time: now.UTC(), Valid: true},
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
