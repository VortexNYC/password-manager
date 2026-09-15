package glue

import (
	"context"
	"fmt"
	"strings"
)

// InviteIdentity is Kratos invite + Keto owner/member.
// Kratos creates the human. Keto records whether they may act in the org.
func (g *Glue) InviteIdentity(ctx context.Context, email, actor string) (Invite, error) {
	if g.humans == nil {
		return Invite{}, fmt.Errorf("glue: kratos admin is required")
	}
	email = strings.TrimSpace(email)
	if !strings.Contains(email, "@") || strings.ContainsAny(email, " \t\n") {
		return Invite{}, fmt.Errorf("glue: email")
	}
	if g.members != nil {
		if err := g.members.RequireOwner(ctx, actor); err != nil {
			return Invite{}, err
		}
	}
	inv, err := g.humans.Invite(ctx, email, g.org())
	if err != nil {
		return Invite{}, err
	}
	if err := g.addOrgMember(ctx, inv.IdentityID); err != nil {
		return Invite{}, err
	}
	return inv, nil
}

// ListMembers is the Kratos directory for this org. Membership checks are Keto.
func (g *Glue) ListMembers(ctx context.Context) ([]string, error) {
	if g.humans == nil {
		return nil, fmt.Errorf("glue: kratos admin is required")
	}
	return g.humans.List(ctx, g.org())
}
