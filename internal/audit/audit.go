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

// ErrClosed is returned by Async.Append after Close has started.
var ErrClosed = errors.New("audit: closed")

// Async queues events in memory and flushes them from a worker.
//
// Backpressure: Append blocks until the queue has room, the auditor is closed,
// or the caller's context is canceled. If the caller's context is canceled
// before the event is queued, the event is dropped and ctx.Err() is returned.
type Async struct {
	store store.Store
	ch    chan protocol.AuditEvent

	mu       sync.Mutex
	closed   bool
	senderWg sync.WaitGroup
	stopCh   chan struct{}

	workerDone chan struct{}
	workerWg   sync.WaitGroup

	errMu sync.Mutex
	err   error

	closeOnce sync.Once
}

func NewAsync(s store.Store, cap int) *Async {
	a := &Async{
		store:      s,
		ch:         make(chan protocol.AuditEvent, cap),
		stopCh:     make(chan struct{}),
		workerDone: make(chan struct{}),
	}
	a.workerWg.Add(1)
	go a.loop()
	return a
}

func (a *Async) Append(ctx context.Context, e protocol.AuditEvent) error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return ErrClosed
	}
	a.senderWg.Add(1)
	a.mu.Unlock()

	select {
	case a.ch <- e:
		a.senderWg.Done()
		return nil
	case <-a.stopCh:
		a.senderWg.Done()
		return ErrClosed
	case <-ctx.Done():
		a.senderWg.Done()
		return ctx.Err()
	}
}

func (a *Async) loop() {
	defer a.workerWg.Done()
	defer close(a.workerDone)
	for e := range a.ch {
		if err := a.store.AppendAudit(e); err != nil {
			a.errMu.Lock()
			if a.err == nil {
				a.err = err
			}
			a.errMu.Unlock()
		}
	}
}

func (a *Async) Close() error {
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		a.mu.Unlock()

		close(a.stopCh)
		a.senderWg.Wait()
		close(a.ch)
	})

	<-a.workerDone
	a.errMu.Lock()
	defer a.errMu.Unlock()
	return a.err
}

var (
	_ Auditor = (*Sync)(nil)
	_ Auditor = (*Async)(nil)
)

// IsDropped returns true if an Append returned because the auditor was closed
// or the caller's context was canceled before the event could be queued. This
// is a best-effort signal and should be logged; it does not make the event durable.
func IsDropped(err error) bool {
	if errors.Is(err, ErrClosed) {
		return true
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
