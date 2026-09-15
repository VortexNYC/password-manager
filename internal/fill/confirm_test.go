package fill

import (
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestConfirmMissingFailsClosed(t *testing.T) {
	h := &Host{}
	if err := h.confirm("Veil wants to fill a password", "github.com", true); err == nil {
		t.Fatal("nil Confirm must fail closed")
	}
}

func TestConfirmScopeReuseWindowAndCVV(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var n atomic.Int32
		h := &Host{Confirm: func(string) error {
			n.Add(1)
			return nil
		}}
		if err := h.confirm("pw", "github.com", true); err != nil {
			t.Fatal(err)
		}
		if err := h.confirm("pw", "github.com", true); err != nil {
			t.Fatal(err)
		}
		if n.Load() != 1 {
			t.Fatalf("same scope %d", n.Load())
		}
		if err := h.confirm("pw", "amazon.com", true); err != nil {
			t.Fatal(err)
		}
		if n.Load() != 2 {
			t.Fatalf("cross scope %d", n.Load())
		}
		if err := h.confirm("cvv", "amazon.com", false); err != nil {
			t.Fatal(err)
		}
		if err := h.confirm("cvv", "amazon.com", false); err != nil {
			t.Fatal(err)
		}
		if n.Load() != 4 {
			t.Fatalf("cvv reused %d", n.Load())
		}

		n.Store(0)
		h = &Host{Confirm: func(string) error {
			n.Add(1)
			return nil
		}}
		if err := h.confirm("pw", "github.com", true); err != nil {
			t.Fatal(err)
		}
		time.Sleep(confirmReuse)
		if err := h.confirm("pw", "github.com", true); err != nil {
			t.Fatal(err)
		}
		if n.Load() != 2 {
			t.Fatalf("window %d", n.Load())
		}
	})
}

func TestConfirmDeniedClearsReuse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var n atomic.Int32
		h := &Host{Confirm: func(string) error {
			n.Add(1)
			return nil
		}}
		if err := h.confirm("pw", "github.com", true); err != nil {
			t.Fatal(err)
		}
		h.Confirm = func(string) error { return errors.New("no") }
		if err := h.confirm("pw", "amazon.com", true); err == nil {
			t.Fatal("denied")
		}
		h.Confirm = func(string) error {
			n.Add(1)
			return nil
		}
		if err := h.confirm("pw", "github.com", true); err != nil {
			t.Fatal(err)
		}
		if n.Load() != 2 {
			t.Fatalf("deny must not leave github armed %d", n.Load())
		}
	})
}
