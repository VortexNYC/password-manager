package passkey

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

func creationPK(t *testing.T, challenge, rpID, userID string, algs []int) json.RawMessage {
	t.Helper()
	params := make([]algJSON, 0, len(algs))
	for _, a := range algs {
		params = append(params, algJSON{Type: "public-key", Alg: a})
	}
	raw, err := json.Marshal(pubKeyJSON{
		Challenge:        challenge,
		PubKeyCredParams: params,
		RP:               rpJSON{ID: rpID, Name: rpID},
		User:             userJSON{ID: userID, Name: "ada", DisplayName: "Ada"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func requestPK(t *testing.T, challenge, rpID, credID string) json.RawMessage {
	t.Helper()
	pk := pubKeyJSON{Challenge: challenge, RpID: rpID}
	if credID != "" {
		pk.AllowCredentials = []credJSON{{ID: credID, Type: "public-key"}}
	}
	raw, err := json.Marshal(pk)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRegisterThenAssert(t *testing.T) {
	origin := "https://github.com"
	create := creationPK(t, "dGVzdGNoYWxsZW5nZQ", "github.com", "dXNlcg", []int{algES256})
	cred, rec, code := Register(origin, create, nil)
	if code != 0 {
		t.Fatalf("register %d", code)
	}
	if rec.PEM == "" || rec.CredID == "" || rec.RpID != "github.com" {
		t.Fatalf("%+v", rec)
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "BEGIN") || strings.Contains(string(raw), rec.PEM[:20]) {
		t.Fatal("credential JSON leaked the private key")
	}
	get := requestPK(t, "Z2V0Y2hhbGxlbmdlMTIz", "github.com", rec.CredID)
	got, code := Assert(origin, get, []Record{rec})
	if code != 0 {
		t.Fatalf("assert %d", code)
	}
	priv, err := parsePEM(rec.PEM)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := DecodeB64(got.Response.AuthenticatorData)
	if err != nil {
		t.Fatal(err)
	}
	client, err := DecodeB64(got.Response.ClientDataJSON)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := DecodeB64(got.Response.Signature)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(client)
	msg := append(append([]byte{}, auth...), sum[:]...)
	if !ecdsa.VerifyASN1(&priv.PublicKey, msg, sig) {
		t.Fatal("assertion signature")
	}
}

func TestRegisterRejectsHTTPAndBadAlg(t *testing.T) {
	pk := creationPK(t, "dGVzdGNoYWxsZW5nZQ", "example.com", "dXNlcg", []int{algES256})
	if _, _, code := Register("http://example.com", pk, nil); code != ErrInvalidURL {
		t.Fatalf("http origin %d", code)
	}
	rs256 := creationPK(t, "dGVzdGNoYWxsZW5nZQ", "example.com", "dXNlcg", []int{-257})
	if _, _, code := Register("https://example.com", rs256, nil); code != ErrNoSupportedAlgs {
		t.Fatalf("rs256 %d", code)
	}
}

func TestAssertNoMatch(t *testing.T) {
	get := requestPK(t, "Z2V0Y2hhbGxlbmdlMTIz", "github.com", "missing")
	if _, code := Assert("https://github.com", get, nil); code != ErrNoLogins {
		t.Fatalf("empty %d", code)
	}
}

func TestLocalhostHTTPAllowed(t *testing.T) {
	pk := creationPK(t, "dGVzdGNoYWxsZW5nZQ", "localhost", "dXNlcg", nil)
	if _, rec, code := Register("http://localhost:3000", pk, nil); code != 0 || rec.RpID != "localhost" {
		t.Fatalf("localhost %d %+v", code, rec)
	}
}
