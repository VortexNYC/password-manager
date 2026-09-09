// Package grant evaluates whether a principal may Use an item.
//
// Stolen shape: Infisical's agent-vs-role split, OneCLI's per-agent rules.
// Ours: the grant is the object (level, actions, expiry), not a vault role.
package grant

import (
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/vortexnyc/password-manager/internal/protocol"
)

type Input struct {
	Principal protocol.Principal
	Item      protocol.Item
	Grant     *protocol.Grant
	Action    protocol.ActionKind
	TargetURL string
	Approval  *protocol.Approval
	Now       time.Time
}

func Evaluate(in Input) protocol.UseResult {
	if in.Principal.Kind != protocol.PrincipalAgent {
		return deny("human_cannot_use")
	}
	if in.Grant == nil {
		return deny("no_grant")
	}
	g := in.Grant
	if g.OrgID != in.Principal.OrgID || g.OrgID != in.Item.OrgID {
		return deny("wrong_org")
	}
	if g.AgentID != in.Principal.ID {
		return deny("wrong_agent")
	}
	if g.ItemID != in.Item.ID {
		return deny("wrong_item")
	}
	if g.ExpiresAt != nil && !in.Now.Before(*g.ExpiresAt) {
		return deny("grant_expired")
	}
	if !slices.Contains(g.Actions, in.Action) {
		return deny("action_not_allowed")
	}
	if in.Action == protocol.ActionFetch {
		if err := hostAllowed(in.Item, in.TargetURL); err != "" {
			return deny(err)
		}
	}
	switch g.Level {
	case protocol.Level2:
		return protocol.UseResult{Decision: protocol.DecisionAllow}
	case protocol.Level1:
		if in.Approval == nil || in.Approval.GrantID != g.ID {
			return protocol.UseResult{Decision: protocol.DecisionNeedApproval, Reason: "need_approval"}
		}
		if !in.Now.Before(in.Approval.ExpiresAt) {
			return protocol.UseResult{Decision: protocol.DecisionNeedApproval, Reason: "approval_expired"}
		}
		return protocol.UseResult{
			Decision:   protocol.DecisionAllow,
			ApprovalID: in.Approval.ID,
		}
	default:
		return deny("unknown_level")
	}
}

func deny(reason string) protocol.UseResult {
	return protocol.UseResult{Decision: protocol.DecisionDeny, Reason: reason}
}

func hostAllowed(item protocol.Item, rawURL string) string {
	if rawURL == "" {
		return "missing_url"
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "invalid_url"
	}
	want := strings.ToLower(u.Host)
	for _, raw := range item.URIs {
		iu, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if strings.ToLower(iu.Host) == want {
			return ""
		}
	}
	return "host_not_allowed"
}
