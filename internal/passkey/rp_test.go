package passkey

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type rpUser struct {
	id    []byte
	name  string
	creds []webauthn.Credential
}

func (u *rpUser) WebAuthnID() []byte                         { return u.id }
func (u *rpUser) WebAuthnName() string                       { return u.name }
func (u *rpUser) WebAuthnDisplayName() string                { return u.name }
func (u *rpUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func TestRegisterThenAssertAgainstRP(t *testing.T) {
	const origin = "https://webauthn.io"
	wconfig := &webauthn.Config{
		RPDisplayName: "webauthn.io",
		RPID:          "webauthn.io",
		RPOrigins:     []string{origin},
	}
	w, err := webauthn.New(wconfig)
	if err != nil {
		t.Fatal(err)
	}
	user := &rpUser{id: []byte("ada"), name: "ada"}
	creation, session, err := w.BeginRegistration(user)
	if err != nil {
		t.Fatal(err)
	}
	pkJSON, err := json.Marshal(creation.Response)
	if err != nil {
		t.Fatal(err)
	}
	cred, rec, code := Register(origin, pkJSON, nil)
	if code != 0 {
		t.Fatalf("register %d", code)
	}
	body, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	parsed, err := protocol.ParseCredentialCreationResponse(req)
	if err != nil {
		t.Fatal(err)
	}
	out, err := w.CreateCredential(user, *session, parsed)
	if err != nil {
		t.Fatalf("rp create: %v", err)
	}
	user.creds = []webauthn.Credential{*out}

	assertion, asession, err := w.BeginLogin(user)
	if err != nil {
		t.Fatal(err)
	}
	getJSON, err := json.Marshal(assertion.Response)
	if err != nil {
		t.Fatal(err)
	}
	got, code := Assert(origin, getJSON, []Record{rec})
	if code != 0 {
		t.Fatalf("assert %d", code)
	}
	gotBody, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	areq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(gotBody))
	areq.Header.Set("Content-Type", "application/json")
	aparsed, err := protocol.ParseCredentialRequestResponse(areq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ValidateLogin(user, *asession, aparsed); err != nil {
		t.Fatalf("rp login: %v", err)
	}
}

func TestCredentialJSONHasRawID(t *testing.T) {
	raw, err := json.Marshal(Credential{ID: "abc", RawID: "abc", Type: "public-key"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"rawId":"abc"`)) {
		t.Fatalf("%s", raw)
	}
}
