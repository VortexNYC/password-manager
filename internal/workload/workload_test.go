package workload

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/store"
)

type testIssuer struct {
	URL    string
	key    *rsa.PrivateKey
	server *httptest.Server
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	iss := &testIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                iss.URL,
			"jwks_uri":                              iss.URL + "/keys",
			"authorization_endpoint":                iss.URL + "/auth",
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &key.PublicKey,
			KeyID:     "test",
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}}}
		_ = json.NewEncoder(w).Encode(set)
	})
	iss.server = httptest.NewServer(mux)
	iss.URL = iss.server.URL
	t.Cleanup(iss.server.Close)
	return iss
}

func (i *testIssuer) token(t *testing.T, sub, aud string, exp time.Time) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: i.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(sig).Claims(jwt.Claims{
		Issuer:   i.URL,
		Subject:  sub,
		Audience: jwt.Audience{aud},
		Expiry:   jwt.NewNumericDate(exp),
		IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOIDCTokenResolvesBoundAgent(t *testing.T) {
	iss := newTestIssuer(t)
	mem := store.NewMemory()
	agent := protocol.Principal{Kind: protocol.PrincipalAgent, ID: "flue", OrgID: "org"}
	if err := mem.PutAgent(agent); err != nil {
		t.Fatal(err)
	}
	if err := mem.PutWorkload(protocol.Workload{
		AgentID:  agent.ID,
		Issuer:   iss.URL,
		Subject:  "repo:vortexnyc/password-manager:ref:refs/heads/main",
		Audience: "password-manager",
	}); err != nil {
		t.Fatal(err)
	}

	c := New(mem)
	tok := iss.token(t, "repo:vortexnyc/password-manager:ref:refs/heads/main", "password-manager", time.Now().Add(time.Hour))
	got, err := c.Agent(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != agent.ID {
		t.Fatalf("%+v", got)
	}
}

func TestUnknownIssuerNeverTrusted(t *testing.T) {
	mem := store.NewMemory()
	c := New(mem)
	// Well-formed token, issuer we have no binding for. Must fail before discovery.
	raw := "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V2aWwuZXhhbXBsZSIsInN1YiI6IngiLCJhdWQiOiJwYXNzd29yZC1tYW5hZ2VyIn0.sig"
	if _, err := c.Agent(context.Background(), raw); err == nil {
		t.Fatal("untrusted issuer accepted")
	}
}

func TestWrongSubjectDenied(t *testing.T) {
	iss := newTestIssuer(t)
	mem := store.NewMemory()
	if err := mem.PutAgent(protocol.Principal{Kind: protocol.PrincipalAgent, ID: "flue", OrgID: "org"}); err != nil {
		t.Fatal(err)
	}
	if err := mem.PutWorkload(protocol.Workload{
		AgentID:  "flue",
		Issuer:   iss.URL,
		Subject:  "the-real-worker",
		Audience: "password-manager",
	}); err != nil {
		t.Fatal(err)
	}
	c := New(mem)
	tok := iss.token(t, "someone-else", "password-manager", time.Now().Add(time.Hour))
	if _, err := c.Agent(context.Background(), tok); err == nil {
		t.Fatal("wrong subject accepted")
	}
}
