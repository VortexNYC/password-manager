package grant

import (
	"testing"
	"time"

	"github.com/vortexnyc/password-manager/internal/protocol"
)

func fixture(level protocol.GrantLevel) Input {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	return Input{
		Principal: protocol.Principal{Kind: protocol.PrincipalAgent, ID: "agent-1", OrgID: "org-1"},
		Item: protocol.Item{
			ID:    "item-1",
			OrgID: "org-1",
			Name:  "stripe-live",
			Kind:  protocol.ItemAPIKey,
			Owner: protocol.Owner{Kind: protocol.OwnerOrg, ID: "org-1"},
			URIs:  []string{"https://api.stripe.com"},
		},
		Grant: &protocol.Grant{
			ID:      "grant-1",
			OrgID:   "org-1",
			AgentID: "agent-1",
			ItemID:  "item-1",
			Level:   level,
			Actions: []protocol.ActionKind{protocol.ActionFetch},
		},
		Action:    protocol.ActionFetch,
		TargetURL: "https://api.stripe.com/v1/customers",
		Now:       now,
	}
}

func TestLevel2AllowsWithoutApproval(t *testing.T) {
	got := Evaluate(fixture(protocol.Level2))
	if got.Decision != protocol.DecisionAllow {
		t.Fatalf("decision=%s reason=%s", got.Decision, got.Reason)
	}
}

func TestLevel1NeedsApproval(t *testing.T) {
	got := Evaluate(fixture(protocol.Level1))
	if got.Decision != protocol.DecisionNeedApproval {
		t.Fatalf("decision=%s reason=%s", got.Decision, got.Reason)
	}
}

func TestLevel1AllowsWithLiveApproval(t *testing.T) {
	in := fixture(protocol.Level1)
	in.Approval = &protocol.Approval{
		ID:        "appr-1",
		GrantID:   "grant-1",
		HumanID:   "human-1",
		ExpiresAt: in.Now.Add(time.Minute),
	}
	got := Evaluate(in)
	if got.Decision != protocol.DecisionAllow {
		t.Fatalf("decision=%s reason=%s", got.Decision, got.Reason)
	}
	if got.ApprovalID != "appr-1" {
		t.Fatalf("approval id=%s", got.ApprovalID)
	}
}

func TestExpiredApprovalNeedsAgain(t *testing.T) {
	in := fixture(protocol.Level1)
	in.Approval = &protocol.Approval{
		ID:        "appr-1",
		GrantID:   "grant-1",
		HumanID:   "human-1",
		ExpiresAt: in.Now,
	}
	got := Evaluate(in)
	if got.Decision != protocol.DecisionNeedApproval || got.Reason != "approval_expired" {
		t.Fatalf("got %+v", got)
	}
}

func TestHumanCannotUse(t *testing.T) {
	in := fixture(protocol.Level2)
	in.Principal.Kind = protocol.PrincipalHuman
	in.Principal.ID = "human-1"
	got := Evaluate(in)
	if got.Decision != protocol.DecisionDeny || got.Reason != "human_cannot_use" {
		t.Fatalf("got %+v", got)
	}
}

func TestWrongAgentDenied(t *testing.T) {
	in := fixture(protocol.Level2)
	in.Principal.ID = "agent-other"
	got := Evaluate(in)
	if got.Reason != "wrong_agent" {
		t.Fatalf("got %+v", got)
	}
}

func TestHostNotOnItemDenied(t *testing.T) {
	in := fixture(protocol.Level2)
	in.TargetURL = "https://evil.example/steal"
	got := Evaluate(in)
	if got.Reason != "host_not_allowed" {
		t.Fatalf("got %+v", got)
	}
}

func TestExpiredGrantDenied(t *testing.T) {
	in := fixture(protocol.Level2)
	exp := in.Now.Add(-time.Second)
	in.Grant.ExpiresAt = &exp
	got := Evaluate(in)
	if got.Reason != "grant_expired" {
		t.Fatalf("got %+v", got)
	}
}

func TestActionNotOnGrantDenied(t *testing.T) {
	in := fixture(protocol.Level2)
	in.Grant.Actions = nil
	got := Evaluate(in)
	if got.Reason != "action_not_allowed" {
		t.Fatalf("got %+v", got)
	}
}

func TestNoGrantDenied(t *testing.T) {
	in := fixture(protocol.Level2)
	in.Grant = nil
	got := Evaluate(in)
	if got.Reason != "no_grant" {
		t.Fatalf("got %+v", got)
	}
}

func TestHTTPSDefaultPortMatchesBareHost(t *testing.T) {
	in := fixture(protocol.Level2)
	in.Item.URIs = []string{"https://api.stripe.com"}
	in.TargetURL = "https://api.stripe.com:443/v1/customers"
	got := Evaluate(in)
	if got.Decision != protocol.DecisionAllow {
		t.Fatalf("got %+v", got)
	}
}

func TestCanonicalHostCONNECT(t *testing.T) {
	u, err := ParseDest("api.stripe.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if CanonicalHost(u) != "api.stripe.com" {
		t.Fatalf("%q", CanonicalHost(u))
	}
}
