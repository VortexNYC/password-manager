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

	"github.com/VortexNYC/veil/internal/protocol"
	"github.com/VortexNYC/veil/internal/store"
)

type testIssuer struct {
	URL         string
	key         *rsa.PrivateKey
	server      *httptest.Server
	discoveries int
}

func newTestIssuer(tb testing.TB) *testIssuer {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatal(err)
	}
	iss := &testIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		iss.discoveries++
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
	tb.Cleanup(iss.server.Close)
	return iss
}

func (i *testIssuer) token(tb testing.TB, sub, aud string, exp time.Time) string {
	tb.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: i.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
	if err != nil {
		tb.Fatal(err)
	}
	raw, err := jwt.Signed(sig).Claims(jwt.Claims{
		Issuer:   i.URL,
		Subject:  sub,
		Audience: jwt.Audience{aud},
		Expiry:   jwt.NewNumericDate(exp),
		IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
	}).Serialize()
	if err != nil {
		tb.Fatal(err)
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
		Subject:  "repo:VortexNYC/veil:ref:refs/heads/main",
		Audience: "veil",
	}); err != nil {
		t.Fatal(err)
	}

	c := New(mem)
	tok := iss.token(t, "repo:VortexNYC/veil:ref:refs/heads/main", "veil", time.Now().Add(time.Hour))
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
		Audience: "veil",
	}); err != nil {
		t.Fatal(err)
	}
	c := New(mem)
	tok := iss.token(t, "someone-else", "veil", time.Now().Add(time.Hour))
	if _, err := c.Agent(context.Background(), tok); err == nil {
		t.Fatal("wrong subject accepted")
	}
}

func TestProviderDiscoveryCachedAcrossCalls(t *testing.T) {
	iss := newTestIssuer(t)
	mem := store.NewMemory()
	if err := mem.PutAgent(protocol.Principal{Kind: protocol.PrincipalAgent, ID: "flue", OrgID: "org"}); err != nil {
		t.Fatal(err)
	}
	if err := mem.PutWorkload(protocol.Workload{
		AgentID:  "flue",
		Issuer:   iss.URL,
		Subject:  "repo:VortexNYC/veil:ref:refs/heads/main",
		Audience: "veil",
	}); err != nil {
		t.Fatal(err)
	}

	c := New(mem)
	tok := iss.token(t, "repo:VortexNYC/veil:ref:refs/heads/main", "veil", time.Now().Add(time.Hour))
	if _, err := c.Agent(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Agent(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	if iss.discoveries != 1 {
		t.Fatalf("provider discovery called %d times, want 1", iss.discoveries)
	}
}

// Steady-state cost of one workload auth: RS256 verify + three store reads,
// provider and JWKS already cached. Reported per-op so the number is directly
// comparable against the measured session-token path.
func BenchmarkAgentVerify(b *testing.B) {
	iss := newTestIssuer(b)
	mem := store.NewMemory()
	if err := mem.PutAgent(protocol.Principal{Kind: protocol.PrincipalAgent, ID: "flue", OrgID: "org"}); err != nil {
		b.Fatal(err)
	}
	if err := mem.PutWorkload(protocol.Workload{
		AgentID:  "flue",
		Issuer:   iss.URL,
		Subject:  "repo:VortexNYC/veil:ref:refs/heads/main",
		Audience: "veil",
	}); err != nil {
		b.Fatal(err)
	}
	c := New(mem)
	tok := iss.token(b, "repo:VortexNYC/veil:ref:refs/heads/main", "veil", time.Now().Add(time.Hour))
	// Warm the provider/JWKS cache so the loop measures steady state.
	if _, err := c.Agent(context.Background(), tok); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Agent(context.Background(), tok); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAgentVerifyParallel(b *testing.B) {
	iss := newTestIssuer(b)
	mem := store.NewMemory()
	if err := mem.PutAgent(protocol.Principal{Kind: protocol.PrincipalAgent, ID: "flue", OrgID: "org"}); err != nil {
		b.Fatal(err)
	}
	if err := mem.PutWorkload(protocol.Workload{
		AgentID:  "flue",
		Issuer:   iss.URL,
		Subject:  "repo:VortexNYC/veil:ref:refs/heads/main",
		Audience: "veil",
	}); err != nil {
		b.Fatal(err)
	}
	c := New(mem)
	tok := iss.token(b, "repo:VortexNYC/veil:ref:refs/heads/main", "veil", time.Now().Add(time.Hour))
	if _, err := c.Agent(context.Background(), tok); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := c.Agent(context.Background(), tok); err != nil {
				b.Fatal(err)
			}
		}
	})
	if iss.discoveries != 1 {
		b.Fatalf("provider discovery called %d times, want 1", iss.discoveries)
	}
}
