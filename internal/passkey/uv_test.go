package passkey

import (
	"encoding/json"
	"testing"
)

func TestRegisterWithoutVerifiedIsCanceled(t *testing.T) {
	create := creationPK(t, "dGVzdGNoYWxsZW5nZQ", "github.com", "dXNlcg", []int{algES256})
	cred, rec, code := Register("https://github.com", create, nil, false)
	if code != ErrCanceled {
		t.Fatalf("unverified register %d", code)
	}
	if cred.ID != "" || rec.PEM != "" {
		t.Fatal("unverified register minted a credential")
	}
}

func TestRegisterDiscouragedWithoutVerifiedIsStillCanceled(t *testing.T) {
	raw, err := json.Marshal(pubKeyJSON{
		Challenge:        "dGVzdGNoYWxsZW5nZQ",
		UserVerification: "discouraged",
		PubKeyCredParams: []algJSON{{Type: "public-key", Alg: algES256}},
		RP:               rpJSON{ID: "github.com", Name: "GitHub"},
		User:             userJSON{ID: "dXNlcg", Name: "ada", DisplayName: "Ada"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, code := Register("https://github.com", raw, nil, false)
	if code != ErrCanceled {
		t.Fatalf("discouraged is not a skip: %d", code)
	}
}

func TestRegisterSetsUVOnlyWhenVerified(t *testing.T) {
	create := creationPK(t, "dGVzdGNoYWxsZW5nZQ", "github.com", "dXNlcg", []int{algES256})
	cred, _, code := Register("https://github.com", create, nil, true)
	if code != 0 {
		t.Fatalf("verified register %d", code)
	}
	flags := authFlags(t, cred.Response.AuthenticatorData)
	if flags&flagUP == 0 || flags&flagUV == 0 {
		t.Fatalf("verified UV flags %08b", flags)
	}
}

func TestAssertWithoutVerifiedIsCanceled(t *testing.T) {
	create := creationPK(t, "dGVzdGNoYWxsZW5nZQ", "github.com", "dXNlcg", []int{algES256})
	_, rec, code := Register("https://github.com", create, nil, true)
	if code != 0 {
		t.Fatalf("register %d", code)
	}
	get := requestPK(t, "Z2V0Y2hhbGxlbmdlMTIz", "github.com", rec.CredID)
	got, code := Assert("https://github.com", get, []Record{rec}, false)
	if code != ErrCanceled {
		t.Fatalf("unverified assert %d", code)
	}
	if got.Response.Signature != "" {
		t.Fatal("unverified assert signed")
	}
}

func TestAssertSetsUVOnlyWhenVerified(t *testing.T) {
	create := creationPK(t, "dGVzdGNoYWxsZW5nZQ", "github.com", "dXNlcg", []int{algES256})
	_, rec, code := Register("https://github.com", create, nil, true)
	if code != 0 {
		t.Fatalf("register %d", code)
	}
	get := requestPK(t, "Z2V0Y2hhbGxlbmdlMTIz", "github.com", rec.CredID)
	got, code := Assert("https://github.com", get, []Record{rec}, true)
	if code != 0 {
		t.Fatalf("verified assert %d", code)
	}
	flags := authFlags(t, got.Response.AuthenticatorData)
	if flags&flagUV == 0 {
		t.Fatalf("verified assert UV flags %08b", flags)
	}
}

func TestRequiredUVWithoutVerifiedIsCanceled(t *testing.T) {
	raw, err := json.Marshal(pubKeyJSON{
		Challenge:        "dGVzdGNoYWxsZW5nZQ",
		UserVerification: "required",
		PubKeyCredParams: []algJSON{{Type: "public-key", Alg: algES256}},
		RP:               rpJSON{ID: "github.com", Name: "GitHub"},
		User:             userJSON{ID: "dXNlcg", Name: "ada", DisplayName: "Ada"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, code := Register("https://github.com", raw, nil, false)
	if code != ErrCanceled {
		t.Fatalf("required UV without verify %d", code)
	}
}

func authFlags(t *testing.T, b64 string) byte {
	t.Helper()
	raw, err := DecodeB64(b64)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 33 {
		t.Fatalf("authData len %d", len(raw))
	}
	return raw[32]
}
