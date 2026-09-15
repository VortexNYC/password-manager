package totpenroll

import (
	"bytes"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestGenerateSeedMints(t *testing.T) {
	got, err := Generate("Veil", "stripe")
	if err != nil {
		t.Fatal(err)
	}
	if got.Seed == "" {
		t.Fatal("empty seed")
	}
	if !bytes.HasPrefix(got.PNG, []byte("\x89PNG")) {
		t.Fatal("qr is not png")
	}
	code, err := totp.GenerateCode(got.Seed, time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC))
	if err != nil || len(code) != 6 {
		t.Fatalf("mint %q %v", code, err)
	}
}

func TestGenerateRequiresAccount(t *testing.T) {
	if _, err := Generate("Veil", ""); err == nil {
		t.Fatal("empty account")
	}
	if _, err := Generate("", "stripe"); err == nil {
		t.Fatal("empty issuer")
	}
}
