package store

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/VortexNYC/veil/internal/protocol"
)

func putTestSession(t *testing.T, s Store, id string, expiresAt time.Time, revokedAt *time.Time) {
	t.Helper()
	sess := protocol.Session{
		ID:        id,
		OrgID:     "org",
		AgentID:   "claude",
		CreatedAt: expiresAt.Add(-time.Hour).UTC(),
		ExpiresAt: expiresAt.UTC(),
		RevokedAt: revokedAt,
		TTL:       int64(time.Hour.Seconds()),
		MaxTTL:    int64((2 * time.Hour).Seconds()),
	}
	sum := sha256.Sum256([]byte("token-" + id))
	if err := s.PutSession(sess, sum[:]); err != nil {
		t.Fatal(err)
	}
}

func TestSweep(t *testing.T) {
	for _, s := range testStores(t) {
		name := fmt.Sprintf("%T", s)
		t.Run(name, func(t *testing.T) {
			defer s.Close()
			seedSessionStore(t, s)

			now := time.Now().UTC()
			before := now.Add(-24 * time.Hour)

			live := now.Add(24 * time.Hour)
			old := now.Add(-48 * time.Hour)
			recent := now.Add(-1 * time.Hour)

			putTestSession(t, s, "ses_expired_old", old, nil)       // delete: long expired
			putTestSession(t, s, "ses_expired_recent", recent, nil) // keep: inside keep window
			putTestSession(t, s, "ses_revoked_old", live, &old)     // delete: revoked long ago
			putTestSession(t, s, "ses_revoked_recent", live, &recent)
			// ses_1 from seedSessionStore is live.

			past := old
			future := now.Add(time.Hour)
			if err := s.PutGrant(protocol.Grant{
				ID: "g_expired", OrgID: "org", AgentID: "claude", ItemID: "other-item",
				Level: protocol.Level1, ExpiresAt: &past,
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.PutGrant(protocol.Grant{
				ID: "g_recent_expired", OrgID: "org", AgentID: "claude", ItemID: "item2",
				Level: protocol.Level1, ExpiresAt: &recent,
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.PutGrant(protocol.Grant{
				ID: "g_live", OrgID: "org", AgentID: "claude", ItemID: "item3",
				Level: protocol.Level1, ExpiresAt: &future,
			}); err != nil {
				t.Fatal(err)
			}

			if err := s.PutApproval(protocol.Approval{
				ID: "ap_expired", GrantID: "g_expired", HumanID: "h", ExpiresAt: old,
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.PutApproval(protocol.Approval{
				ID: "ap_live", GrantID: "g_live", HumanID: "h", ExpiresAt: future,
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.PutApproval(protocol.Approval{
				ID: "ap_recent", GrantID: "g_recent_expired", HumanID: "h", ExpiresAt: recent,
			}); err != nil {
				t.Fatal(err)
			}

			rep, err := s.Sweep(before)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Sessions != 2 || rep.Grants != 1 || rep.Approvals != 1 {
				t.Fatalf("report %+v, want sessions=2 grants=1 approvals=1", rep)
			}

			// Idempotent: a second pass deletes nothing.
			rep, err = s.Sweep(before)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Sessions != 0 || rep.Grants != 0 || rep.Approvals != 0 {
				t.Fatalf("second sweep %+v, want all zeros", rep)
			}

			// Kept rows are still visible through the Store.
			sessions, err := s.ListSessions()
			if err != nil {
				t.Fatal(err)
			}
			if len(sessions) != 3 {
				t.Fatalf("sessions after sweep = %d, want 3", len(sessions))
			}
		})
	}
}
