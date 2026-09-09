package crypto

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("sk_live_do_not_leak")
	blob, err := Seal(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q", got)
	}
}

func TestOpenWrongKeyFails(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Seal(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(other, blob); err != ErrAuth {
		t.Fatalf("err=%v", err)
	}
}

func TestOpenTruncatedFails(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(key, []byte("short")); err != ErrAuth {
		t.Fatalf("err=%v", err)
	}
}

func TestNewKeySize(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != KeySize {
		t.Fatalf("len=%d", len(key))
	}
}
