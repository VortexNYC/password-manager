package publicapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/scrub"
)

const secret = "sk_live_API_SECRET"

func testApp(t *testing.T) *app.App {
	t.Helper()
	a, err := app.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

func identity(tok string) func(context.Context, string) (protocol.Principal, error) {
	return func(_ context.Context, raw string) (protocol.Principal, error) {
		switch raw {
		case "human":
			return protocol.Principal{Kind: protocol.PrincipalHuman, ID: "self", OrgID: protocol.LocalOrgID}, nil
		case "agent":
			return protocol.Principal{Kind: protocol.PrincipalAgent, ID: "claude", OrgID: protocol.LocalOrgID}, nil
		default:
			return protocol.Principal{}, fmt.Errorf("unauthorized")
		}
	}
}

func apiServer(t *testing.T, a *app.App) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	(&Server{App: a, Identity: identity("")}).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func doJSON(t *testing.T, srv *httptest.Server, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, srv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, raw
}

func TestOwnerCreateItemSecretAbsentFromResponse(t *testing.T) {
	a := testApp(t)
	if _, err := a.AddAgent("claude"); err != nil {
		t.Fatal(err)
	}
	srv := apiServer(t, a)
	code, raw := doJSON(t, srv, http.MethodPost, "/v1/items", "human", CreateItemRequest{
		Name:   "github",
		URI:    "https://api.github.com",
		Secret: secret,
	})
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, raw)
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatal("create echoed secret")
	}
	code, raw = doJSON(t, srv, http.MethodGet, "/v1/items", "human", nil)
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, raw)
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatal("list leaked secret")
	}
	if !bytes.Contains(raw, []byte("github")) {
		t.Fatalf("%s", raw)
	}
	code, raw = doJSON(t, srv, http.MethodPost, "/v1/grants", "human", CreateGrantRequest{
		Agent: "claude",
		Item:  "github",
		Level: "level2",
	})
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, raw)
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatal("grant leaked secret")
	}
	code, raw = doJSON(t, srv, http.MethodGet, "/v1/items", "agent", nil)
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, raw)
	}
	if !bytes.Contains(raw, []byte("github")) {
		t.Fatalf("agent list %s", raw)
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatal("agent list leaked secret")
	}
}

func TestAgentCannotCreateItemOrFill(t *testing.T) {
	a := testApp(t)
	if _, err := a.AddItem("github", "https://api.github.com", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddAgent("claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddGrant("claude", "github", protocol.Level2); err != nil {
		t.Fatal(err)
	}
	srv := apiServer(t, a)
	code, raw := doJSON(t, srv, http.MethodPost, "/v1/items", "agent", CreateItemRequest{Name: "x", Secret: secret})
	if code != http.StatusForbidden {
		t.Fatalf("%d %s", code, raw)
	}
	code, raw = doJSON(t, srv, http.MethodPost, "/v1/fill/logins", "agent", FillLoginsRequest{URL: "https://api.github.com"})
	if code != http.StatusForbidden {
		t.Fatalf("fill %d %s", code, raw)
	}
	code, raw = doJSON(t, srv, http.MethodPost, "/v1/fill/logins", "human", FillLoginsRequest{URL: "https://api.github.com/user"})
	if code != http.StatusOK {
		t.Fatalf("human fill %d %s", code, raw)
	}
	if !scrub.Contains(raw, []byte(secret)) {
		t.Fatal("human fill missing password")
	}
	code, specRaw := doJSON(t, srv, http.MethodGet, "/openapi.json", "", nil)
	if code != http.StatusOK {
		t.Fatalf("spec %d", code)
	}
	if bytes.Contains(specRaw, []byte("/v1/fill")) {
		t.Fatal("fill is on the generated contract")
	}
}

func TestFillPathNotInOpenAPI(t *testing.T) {
	if bytes.Contains(Spec, []byte("/v1/fill")) {
		t.Fatal("fill is GetSecret; not on the generated contract")
	}
}
