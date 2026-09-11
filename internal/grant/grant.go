// Package grant evaluates whether a principal may Use an item.
//
// Shape follows Infisical's agent-vs-role split and OneCLI's per-agent rules.
// Ours: the grant is the object (level, actions, expiry), not a vault role.
package grant

import (
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/vortexnyc/password-manager/internal/protocol"
)

var errEmptyDest = errors.New("grant: empty destination")

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
	if in.Item.Archived {
		return deny("item_archived")
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
	if !actionAllowed(g.Actions, in.Action) {
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

func actionAllowed(actions []protocol.ActionKind, want protocol.ActionKind) bool {
	if slices.Contains(actions, want) {
		return true
	}
	// Env into a child is Use of a granted item. Fetch on the grant is that Use.
	return want == protocol.ActionEnv && slices.Contains(actions, protocol.ActionFetch)
}

func deny(reason string) protocol.UseResult {
	return protocol.UseResult{Decision: protocol.DecisionDeny, Reason: reason}
}

func hostAllowed(item protocol.Item, rawURL string) string {
	if rawURL == "" {
		return "missing_url"
	}
	u, err := ParseDest(rawURL)
	if err != nil {
		return "invalid_url"
	}
	want := CanonicalHost(u)
	if want == "" {
		return "invalid_url"
	}
	for _, raw := range item.URIs {
		iu, err := ParseDest(raw)
		if err != nil {
			continue
		}
		if CanonicalHost(iu) == want {
			return ""
		}
	}
	return "host_not_allowed"
}

// ParseDest accepts an absolute URL or a CONNECT host:port.
func ParseDest(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errEmptyDest
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, errEmptyDest
	}
	return u, nil
}

// CanonicalHost is hostname, plus port when it is not the scheme default.
func CanonicalHost(u *url.URL) string {
	if u == nil {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	if h == "" {
		return ""
	}
	port := u.Port()
	scheme := strings.ToLower(u.Scheme)
	if port == "" || (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return h
	}
	return h + ":" + port
}

func HostAllowed(item protocol.Item, rawURL string) bool {
	return hostAllowed(item, rawURL) == ""
}
