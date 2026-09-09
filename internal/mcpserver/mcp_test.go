package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/scrub"
)

const secret = "sk_live_MCP_SECRET"

func TestMCPFetchDoesNotReturnSecret(t *testing.T) {
	a, err := app.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("Authorization"))
	}))
	t.Cleanup(upstream.Close)
	if _, err := a.AddItem("stripe", upstream.URL, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddAgent("claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddGrant("claude", "stripe", "level2"); err != nil {
		t.Fatal(err)
	}

	if _, err := New(a, "missing"); err == nil {
		t.Fatal("bound unknown agent")
	}
	if _, err := New(a, "claude"); err != nil {
		t.Fatal(err)
	}

	out, err := Fetch(context.Background(), a, "claude", FetchIn{Item: "stripe", URL: upstream.URL + "/v1"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Decision != "allow" {
		t.Fatalf("%+v", out)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatalf("mcp output leaked secret: %s", raw)
	}

	items, err := a.ItemsForAgent("claude")
	if err != nil {
		t.Fatal(err)
	}
	list, err := json.Marshal(ListOut{Items: items})
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(list, []byte(secret)) {
		t.Fatal("list_items leaked secret")
	}
}
