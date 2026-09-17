package store

import (
	"errors"
	"testing"
)

// retryable models pgconn's conn-level errors: anything implementing
// SafeToRetry() bool is classified by pgconn.SafeToRetry.
type retryable struct{ safe bool }

func (e retryable) Error() string     { return "conn dead before send" }
func (e retryable) SafeToRetry() bool { return e.safe }

func TestRetryOnDeadConnRetriesOnce(t *testing.T) {
	calls := 0
	v, err := retryOnDeadConn(func() (int, error) {
		calls++
		if calls == 1 {
			return 0, retryable{safe: true}
		}
		return 42, nil
	})
	if err != nil || v != 42 {
		t.Fatalf("v=%d err=%v", v, err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d, want 2", calls)
	}
}

func TestRetryOnDeadConnBounded(t *testing.T) {
	calls := 0
	_, err := retryOnDeadConn(func() (int, error) {
		calls++
		return 0, retryable{safe: true}
	})
	if err == nil {
		t.Fatal("want error")
	}
	if calls != 2 {
		t.Fatalf("calls=%d, want exactly 2 (one retry)", calls)
	}
}

func TestRetryOnDeadConnDoesNotRetryQueryErrors(t *testing.T) {
	calls := 0
	sentinel := errors.New("constraint violation")
	_, err := retryOnDeadConn(func() (int, error) {
		calls++
		return 0, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v", err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d, want 1 — query errors must not retry", calls)
	}
}

func TestRetryOnDeadConnDoesNotRetryUnsafe(t *testing.T) {
	calls := 0
	_, err := retryOnDeadConn(func() (int, error) {
		calls++
		return 0, retryable{safe: false}
	})
	if err == nil {
		t.Fatal("want error")
	}
	if calls != 1 {
		t.Fatalf("calls=%d, want 1 — SafeToRetry=false must not retry", calls)
	}
}
