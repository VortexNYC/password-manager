// Package audit decouples security-event persistence from request handling.
//
// The synchronous path writes every audit event to the store before the caller
// returns. The asynchronous path queues events in memory and flushes them from
// a worker, so the hot Use path does not wait for a store round trip per event.
//
// Durability semantics are explicit: Async buffers in memory. A process crash
// before a flush loses queued events. Callers must call Close to drain.
package audit

import (
	"context"
	"errors"
	"sync"

	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/store"
)

// Auditor persists security events. Implementations may be synchronous or
// buffered. Close must be called before the owning store is closed.
type Auditor interface {
	Append(ctx context.Context, e protocol.AuditEvent) error
	Close() error
}

// Sync writes every event directly to the store.
type Sync struct {
	Store store.Store
}

func (s *Sync) Append(ctx context.Context, e protocol.AuditEvent) error {
	return s.Store.AppendAudit(e)
}

func (s *Sync) Close() error { return nil }

// Async queues events in memory and flushes them from a worker.
//
// Backpressure: Append blocks until the queue has room or the context is
// canceled. If the caller's context is canceled before the event is queued,
// the event is dropped and ctx.Err() is returned.
type Async struct {
	store store.Store
	ch    chan protocol.AuditEvent

	wg  sync.WaitGroup
	mu  sync.Mutex
	err error
}

func NewAsync(s store.Store, cap int) *Async {
	a := &Async{store: s, ch: make(chan protocol.AuditEvent, cap)}
	a.wg.Add(1)
	go a.loop()
	return a
}

func (a *Async) Append(ctx context.Context, e protocol.AuditEvent) error {
	select {
	case a.ch <- e:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *Async) loop() {
	defer a.wg.Done()
	for e := range a.ch {
		if err := a.store.AppendAudit(e); err != nil {
			a.mu.Lock()
			if a.err == nil {
				a.err = err
			}
			a.mu.Unlock()
		}
	}
}

func (a *Async) Close() error {
	close(a.ch)
	a.wg.Wait()
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

var (
	_ Auditor = (*Sync)(nil)
	_ Auditor = (*Async)(nil)
)

// IsDropped returns true if an Append returned because the caller's context
// was canceled before the event could be queued. This is a best-effort signal
// and should be logged; it does not make the event durable.
func IsDropped(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
