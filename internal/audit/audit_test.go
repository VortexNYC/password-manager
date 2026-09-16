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
	m := &slowStore{Memory: store.NewMemory(), delay: 5 * time.Second}
	a := NewAsync(m, 0)

	// Occupy the worker so the next send cannot proceed.
	if err := a.Append(context.Background(), protocol.AuditEvent{AgentID: "first"}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := a.Append(ctx, protocol.AuditEvent{AgentID: "second"})
	if err != context.Canceled {
		t.Fatalf("want context.Canceled, got %v", err)
	}

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	events, _ := m.Audit()
	if len(events) != 1 || events[0].AgentID != "first" {
		t.Fatalf("flushed events=%+v", events)
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

func (s *slowStore) AppendAudits(events []protocol.AuditEvent) error {
	time.Sleep(s.delay)
	return s.Memory.AppendAudits(events)
}

func TestAsyncAuditorWaitsForInterval(t *testing.T) {
	m := store.NewMemory()
	a := NewAsyncWithInterval(m, 4, 200*time.Millisecond)

	for i := 0; i < 3; i++ {
		if err := a.Append(context.Background(), protocol.AuditEvent{AgentID: "a"}); err != nil {
			t.Fatal(err)
		}
	}

	// Events should not be persisted until the flush interval elapses.
	time.Sleep(50 * time.Millisecond)
	events, _ := m.Audit()
	if len(events) != 0 {
		t.Fatalf("want 0 events, got %d", len(events))
	}

	time.Sleep(200 * time.Millisecond)
	events, err := m.Audit()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("want 3 events, got %d", len(events))
	}

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAsyncAuditorFlushesWhenBatchFullBeforeInterval(t *testing.T) {
	m := store.NewMemory()
	a := NewAsyncWithInterval(m, 2, time.Second)

	if err := a.Append(context.Background(), protocol.AuditEvent{AgentID: "first"}); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := a.Append(context.Background(), protocol.AuditEvent{AgentID: "second"}); err != nil {
			t.Error(err)
		}
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("append blocked even though batch is full")
	}

	time.Sleep(20 * time.Millisecond)
	events, err := m.Audit()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events, got %d", len(events))
	}

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAsyncAuditorFlushesPendingOnClose(t *testing.T) {
	m := store.NewMemory()
	a := NewAsyncWithInterval(m, 8, time.Second)

	if err := a.Append(context.Background(), protocol.AuditEvent{AgentID: "pending"}); err != nil {
		t.Fatal(err)
	}

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	events, err := m.Audit()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].AgentID != "pending" {
		t.Fatalf("events=%+v", events)
	}
}
