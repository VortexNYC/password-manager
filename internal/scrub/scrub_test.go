package scrub

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestBytesRedactsPlainAndBase64(t *testing.T) {
	secret := []byte("sk_live_super_secret")
	body := []byte(`got sk_live_super_secret and ` + base64.StdEncoding.EncodeToString(secret))
	got := Bytes(body, secret)
	if Contains(got, secret) {
		t.Fatalf("plain secret leaked: %s", got)
	}
	if bytes.Contains(got, []byte(base64.StdEncoding.EncodeToString(secret))) {
		t.Fatalf("base64 secret leaked: %s", got)
	}
	if !bytes.Contains(got, []byte(Redacted)) {
		t.Fatalf("missing redaction marker: %s", got)
	}
}

func TestEmptySecretIsNoop(t *testing.T) {
	in := []byte("hello")
	if !bytes.Equal(Bytes(in, nil), in) {
		t.Fatal("empty secret changed input")
	}
}
