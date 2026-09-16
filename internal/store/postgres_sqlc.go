package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
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
