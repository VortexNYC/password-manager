package glue

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientCredentialsReturnsJWTNotOpaque(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/token" {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "agent-flue" || pass != "hydra-agent-secret" {
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "client_credentials" {
			t.Fatalf("grant %q", r.Form.Get("grant_type"))
		}
		if r.Form.Get("audience") != DefaultClientID {
			t.Fatalf("audience %q", r.Form.Get("audience"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "aaa.bbb.ccc",
			"token_type":   "bearer",
		})
	}))
	t.Cleanup(s.Close)

	raw, err := ClientCredentials(context.Background(), s.URL, "agent-flue", "hydra-agent-secret", DefaultClientID)
	if err != nil {
		t.Fatal(err)
	}
	if raw != "aaa.bbb.ccc" {
		t.Fatalf("%q", raw)
	}
}

func TestClientCredentialsRejectsOpaque(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ory_at_opaque",
			"token_type":   "bearer",
		})
	}))
	t.Cleanup(s.Close)
	if _, err := ClientCredentials(context.Background(), s.URL, "agent-flue", "s", DefaultClientID); err == nil {
		t.Fatal("accepted opaque")
	}
}

func TestNewHydraDoesNotNeedKratos(t *testing.T) {
	ory := &fakeOry{}
	_, h := ory.start(t)
	g, err := NewHydra(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.EnsureAgent(context.Background(), AgentClient{ID: AgentClientID("flue")}); err != nil {
		t.Fatal(err)
	}
	if ory.inviteN != 0 {
		t.Fatal("called kratos")
	}
	if strings.Contains(gotSecret(ory), humanEmail) {
		t.Fatal("human leaked")
	}
}

func gotSecret(ory *fakeOry) string {
	s, _ := ory.client["client_secret"].(string)
	return s
}
