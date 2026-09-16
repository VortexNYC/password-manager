package audit

import (
	"context"
	"testing"
	"time"

	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/store"
)

func TestSyncAuditorWritesImmediately(t *testing.T) {
	m := store.NewMemory()
	a := &Sync{Store: m}
	e := protocol.AuditEvent{OrgID: "o", AgentID: "a", ItemID: "i", Action: protocol.ActionFetch, Decision: protocol.DecisionAllow}
	if err := a.Append(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	events, err := m.Audit()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events", len(events))
	}
	if events[0].AgentID != "a" {
		t.Fatalf("wrong event: %+v", events[0])
	}
}

func TestAsyncAuditorFlushesOnClose(t *testing.T) {
	m := store.NewMemory()
	a := NewAsync(m, 8)
	e := protocol.AuditEvent{OrgID: "o", AgentID: "a", ItemID: "i", Action: protocol.ActionFetch, Decision: protocol.DecisionAllow}
	if err := a.Append(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	events, err := m.Audit()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].AgentID != "a" {
		t.Fatalf("events=%+v", events)
	}
}

func TestAsyncAuditorRespectsContextCancellation(t *testing.T) {
	m := store.NewMemory()
	a := NewAsync(m, 0)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A zero-capacity channel means the send cannot proceed without the worker
	// reading first; with the context already canceled, Append should return.
	err := a.Append(ctx, protocol.AuditEvent{})
	if err != context.Canceled {
		t.Fatalf("want context.Canceled, got %v", err)
	}

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	events, _ := m.Audit()
	if len(events) != 0 {
		t.Fatalf("canceled event was flushed: %+v", events)
	}
}

func TestAsyncAuditorDropsWhenBackloggedAndContextExpires(t *testing.T) {
	m := &slowStore{Memory: store.NewMemory(), delay: 5 * time.Second}
	a := NewAsync(m, 0)

	// Send one event. The worker reads it and then blocks in the slow store.
	if err := a.Append(context.Background(), protocol.AuditEvent{AgentID: "first"}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := a.Append(ctx, protocol.AuditEvent{AgentID: "second"})
	if !IsDropped(err) {
		t.Fatalf("want dropped, got %v", err)
	}

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
}

type slowStore struct {
	*store.Memory
	delay time.Duration
}

func (s *slowStore) AppendAudit(e protocol.AuditEvent) error {
	time.Sleep(s.delay)
	return s.Memory.AppendAudit(e)
}
