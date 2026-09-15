package device

import (
	"bytes"
	"testing"

	"github.com/vortexnyc/password-manager/internal/crypto"
	"github.com/vortexnyc/password-manager/internal/scrub"
)

func TestOfferAcceptRoundTrip(t *testing.T) {
	master, err := crypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	bPub, bPriv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Offer(master, bPub)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(blob, master) {
		t.Fatal("master in pairing blob")
	}
	if scrub.Contains(blob, bPriv) {
		t.Fatal("private key in pairing blob")
	}
	got, err := Accept(blob, bPriv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, master) {
		t.Fatal("master mismatch")
	}
	pub, err := Public(bPriv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, bPub) {
		t.Fatal("public mismatch")
	}
}

func TestAcceptWrongKeyFails(t *testing.T) {
	master, err := crypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	bPub, _, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, cPriv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Offer(master, bPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Accept(blob, cPriv); err != crypto.ErrAuth {
		t.Fatalf("err=%v", err)
	}
}

func TestAcceptTruncatedFails(t *testing.T) {
	_, priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Accept([]byte("short"), priv); err != crypto.ErrAuth {
		t.Fatalf("err=%v", err)
	}
}
