//go:build liveorigin

package livetest

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/VortexNYC/veil/internal/mcpserver"
)

func TestOriginStdio(t *testing.T) {
	bin, err := exec.LookPath("veil")
	if err != nil {
		t.Fatal("veil not on PATH")
	}
	jwtFile := os.Getenv("VEIL_LIVE_JWT_FILE")
	if jwtFile == "" {
		t.Fatal("VEIL_LIVE_JWT_FILE is required")
	}
	origin := envOr("VEIL_ORIGIN", "https://veil.nyc")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	cmd := exec.Command(bin, "mcp", "stdio")
	cmd.Env = append(os.Environ(),
		"VEIL_ORIGIN="+origin,
		"VEIL_OIDC_TOKEN_FILE="+jwtFile,
		"VEIL_OIDC_TOKEN=",
	)
	client := mcp.NewClient(&mcp.Implementation{Name: "prove-live-stdio", Version: "0"}, nil)
	cs, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	list, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_items"})
	if err != nil {
		t.Fatal(err)
	}
	if list.IsError {
		t.Fatalf("list_items error: %+v", list)
	}
	listRaw, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	assertNoLeak(t, listRaw)
	if !contains(mcpToolItemNames(t, listRaw), "github") {
		t.Fatalf("stdio list missing github: %s", clip(listRaw))
	}

	fetch, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "fetch",
		Arguments: mcpserver.FetchIn{Item: "github", URL: "https://api.github.com/user", Method: "GET"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fetch.IsError {
		t.Fatalf("fetch error: %+v", fetch)
	}
	fetchRaw, err := json.Marshal(fetch)
	if err != nil {
		t.Fatal(err)
	}
	assertNoLeak(t, fetchRaw)
	if !bytes.Contains(fetchRaw, []byte(`"decision":"allow"`)) {
		t.Fatalf("stdio fetch %s", clip(fetchRaw))
	}
}

func mcpToolItemNames(t *testing.T, raw []byte) []string {
	t.Helper()
	var wrap struct {
		StructuredContent struct {
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
		} `json:"structuredContent"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(wrap.StructuredContent.Items))
	for _, it := range wrap.StructuredContent.Items {
		names = append(names, it.Name)
	}
	return names
}
