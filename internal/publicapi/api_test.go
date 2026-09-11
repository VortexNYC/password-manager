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
		case "member":
			return protocol.Principal{Kind: protocol.PrincipalHuman, ID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", OrgID: protocol.LocalOrgID}, nil
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
	pk, err := json.Marshal(map[string]any{
		"challenge": "dGVzdGNoYWxsZW5nZQ",
		"rpId":      "github.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	code, raw = doJSON(t, srv, http.MethodPost, "/v1/fill/passkeys/get", "agent", FillPasskeysRequest{
		Origin:    "https://github.com",
		PublicKey: pk,
	})
	if code != http.StatusForbidden {
		t.Fatalf("agent passkeys %d %s", code, raw)
	}
}

func TestFillPathNotInOpenAPI(t *testing.T) {
	if bytes.Contains(Spec, []byte("/v1/fill")) {
		t.Fatal("fill is GetSecret; not on the generated contract")
	}
}

func TestFillLoginIsUsernameNotName(t *testing.T) {
	const login = "stripe@example.com"
	a := testApp(t)
	srv := apiServer(t, a)
	code, raw := doJSON(t, srv, http.MethodPost, "/v1/items", "human", CreateItemRequest{
		Name:   "stripe",
		URI:    "https://dashboard.stripe.com",
		Secret: secret,
		Login:  login,
	})
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, raw)
	}
	if scrub.Contains(raw, []byte(login)) || scrub.Contains(raw, []byte(secret)) {
		t.Fatal("create echoed login or secret")
	}
	code, raw = doJSON(t, srv, http.MethodGet, "/v1/items", "human", nil)
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, raw)
	}
	if scrub.Contains(raw, []byte(login)) {
		t.Fatal("list leaked login")
	}
	code, raw = doJSON(t, srv, http.MethodPost, "/v1/fill/logins", "human", FillLoginsRequest{URL: "https://dashboard.stripe.com/login"})
	if code != http.StatusOK {
		t.Fatalf("fill %d %s", code, raw)
	}
	var got FillLoginsResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Login != login || got.Entries[0].Name != "stripe" || got.Entries[0].Password != secret {
		t.Fatalf("%+v", got)
	}
	code, raw = doJSON(t, srv, http.MethodPatch, "/v1/items/stripe", "human", UpdateItemRequest{Login: "other@example.com"})
	if code != http.StatusOK {
		t.Fatalf("update %d %s", code, raw)
	}
	if scrub.Contains(raw, []byte("other@example.com")) {
		t.Fatal("update echoed login")
	}
	code, raw = doJSON(t, srv, http.MethodPost, "/v1/fill/logins", "human", FillLoginsRequest{URL: "https://dashboard.stripe.com/login"})
	if code != http.StatusOK {
		t.Fatalf("fill after update %d %s", code, raw)
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Login != "other@example.com" || got.Entries[0].Password != secret {
		t.Fatalf("update rotated or missed login: %+v", got)
	}
}

func TestUpdateItemURIAddsWithoutDropping(t *testing.T) {
	a := testApp(t)
	srv := apiServer(t, a)
	code, raw := doJSON(t, srv, http.MethodPost, "/v1/items", "human", CreateItemRequest{
		Name:   "github",
		URI:    "https://api.github.com",
		Secret: secret,
	})
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, raw)
	}
	code, raw = doJSON(t, srv, http.MethodPatch, "/v1/items/github", "human", UpdateItemRequest{URI: "https://github.com"})
	if code != http.StatusOK {
		t.Fatalf("add %d %s", code, raw)
	}
	var item protocol.Item
	if err := json.Unmarshal(raw, &item); err != nil {
		t.Fatal(err)
	}
	if len(item.URIs) != 2 || item.URIs[0] != "https://api.github.com" || item.URIs[1] != "https://github.com" {
		t.Fatalf("uri dropped a host: %+v", item.URIs)
	}
	code, raw = doJSON(t, srv, http.MethodPatch, "/v1/items/github", "human", UpdateItemRequest{URIs: []string{"https://github.com"}})
	if code != http.StatusOK {
		t.Fatalf("replace %d %s", code, raw)
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		t.Fatal(err)
	}
	if len(item.URIs) != 1 || item.URIs[0] != "https://github.com" {
		t.Fatalf("uris did not replace: %+v", item.URIs)
	}
}

type fakeMembers struct {
	owners  map[string]bool
	members map[string]bool
}

func (f fakeMembers) IsMember(_ context.Context, id string) (bool, error) {
	return f.members[id], nil
}

func (f fakeMembers) IsOwner(_ context.Context, id string) (bool, error) {
	return f.owners[id], nil
}

func TestHumanGrantAPI(t *testing.T) {
	const member = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	a := testApp(t)
	a.Members = fakeMembers{members: map[string]bool{member: true}}
	if _, err := a.AddItem("github", "https://api.github.com", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	srv := apiServer(t, a)
	code, raw := doJSON(t, srv, http.MethodPost, "/v1/fill/logins", "member", FillLoginsRequest{URL: "https://api.github.com/user"})
	if code != http.StatusOK {
		t.Fatalf("member fill before grant %d %s", code, raw)
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatal("member filled without grant")
	}
	code, raw = doJSON(t, srv, http.MethodPost, "/v1/grants", "member", CreateGrantRequest{
		Human: member,
		Item:  "github",
		Level: "level2",
	})
	if code != http.StatusForbidden {
		t.Fatalf("member created grant %d %s", code, raw)
	}
	code, raw = doJSON(t, srv, http.MethodPost, "/v1/grants", "human", CreateGrantRequest{
		Human: "not-an-email@example.com",
		Item:  "github",
		Level: "level2",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("email as human %d %s", code, raw)
	}
	code, raw = doJSON(t, srv, http.MethodPost, "/v1/grants", "human", CreateGrantRequest{
		Agent: "claude",
		Human: member,
		Item:  "github",
		Level: "level2",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("agent and human %d %s", code, raw)
	}
	code, raw = doJSON(t, srv, http.MethodPost, "/v1/grants", "human", CreateGrantRequest{
		Human: member,
		Item:  "github",
		Level: "level2",
	})
	if code != http.StatusOK {
		t.Fatalf("human grant %d %s", code, raw)
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatal("grant leaked secret")
	}
	if !bytes.Contains(raw, []byte(member)) {
		t.Fatalf("grant missing grantee %s", raw)
	}
	code, raw = doJSON(t, srv, http.MethodPost, "/v1/fill/logins", "member", FillLoginsRequest{URL: "https://api.github.com/user"})
	if code != http.StatusOK {
		t.Fatalf("member fill %d %s", code, raw)
	}
	if !scrub.Contains(raw, []byte(secret)) {
		t.Fatal("granted member missing password")
	}
	code, raw = doJSON(t, srv, http.MethodGet, "/v1/items", "member", nil)
	if code != http.StatusOK {
		t.Fatalf("member list %d %s", code, raw)
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatal("member list leaked secret")
	}
	if !bytes.Contains(raw, []byte("github")) {
		t.Fatalf("member list %s", raw)
	}
}

func TestOwnerAgentsNoSecret(t *testing.T) {
	a := testApp(t)
	srv := apiServer(t, a)
	code, raw := doJSON(t, srv, http.MethodPost, "/v1/agents", "human", CreateAgentRequest{Name: "flue"})
	if code != http.StatusOK {
		t.Fatalf("create %d %s", code, raw)
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatal("create agent leaked secret")
	}
	if !bytes.Contains(raw, []byte(`"flue"`)) {
		t.Fatalf("create %s", raw)
	}
	code, raw = doJSON(t, srv, http.MethodGet, "/v1/agents", "human", nil)
	if code != http.StatusOK {
		t.Fatalf("list %d %s", code, raw)
	}
	if !bytes.Contains(raw, []byte("flue")) {
		t.Fatalf("list %s", raw)
	}
	code, raw = doJSON(t, srv, http.MethodGet, "/v1/agents", "agent", nil)
	if code != http.StatusForbidden {
		t.Fatalf("agent list %d %s", code, raw)
	}
}

func TestCORSPreflightVaultOrigin(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/items", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(CORS(mux))
	t.Cleanup(srv.Close)
	req, err := http.NewRequest(http.MethodOptions, srv.URL+"/v1/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://app.veil.nyc")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "authorization")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", res.StatusCode)
	}
	if got := res.Header.Get("Access-Control-Allow-Origin"); got != "https://app.veil.nyc" {
		t.Fatalf("origin %q", got)
	}
}

func TestCORSUnknownOrigin(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/items", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(CORS(mux))
	t.Cleanup(srv.Close)
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://evil.example")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if got := res.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("origin %q", got)
	}
}
