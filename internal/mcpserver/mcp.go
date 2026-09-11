// Package mcpserver is the agent surface: Streamable HTTP MCP.
//
// Official SDK: github.com/modelcontextprotocol/go-sdk/mcp
// Source: https://github.com/modelcontextprotocol/go-sdk (v1.7.0)
// Spec: https://modelcontextprotocol.io/specification/2025-03-26/basic/transports
//
// Identity is the Bearer token (Hydra JWT / bound OIDC). The host is not
// identity. Tools return Use results, never secrets.
package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/protocol"
)

type FetchIn struct {
	Item    string            `json:"item" jsonschema:"item name the agent is granted"`
	URL     string            `json:"url" jsonschema:"URL to fetch; host must match the item"`
	Method  string            `json:"method,omitempty" jsonschema:"HTTP method, default GET"`
	Headers map[string]string `json:"headers,omitempty" jsonschema:"extra request headers. never the vault secret"`
	Body    string            `json:"body,omitempty" jsonschema:"request body. never the vault secret"`
}

type FetchOut struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
	Status   int    `json:"status,omitempty"`
	Body     string `json:"body,omitempty"`
}

type ListOut struct {
	Items []protocol.Item `json:"items"`
}

func New(a *app.App) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "veil", Version: "0.0.1"}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_items",
		Description: "List items this agent may Use. Names and URIs only. Never secrets.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ListOut, error) {
		agentID, err := principal(req)
		if err != nil {
			return nil, ListOut{}, err
		}
		items, err := a.ItemsForAgent(agentID)
		if err != nil {
			return nil, ListOut{}, err
		}
		if items == nil {
			items = []protocol.Item{}
		}
		slog.Info("mcp", "tool", "list_items", "agent", agentID, "n", len(items))
		return nil, ListOut{Items: items}, nil
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "fetch",
		Description: "Call a URL as this agent. The broker injects the credential. You never receive the secret. Level-1 items return decision=need_approval until a human runs `password-manager approve`.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in FetchIn) (*mcp.CallToolResult, FetchOut, error) {
		agentID, err := principal(req)
		if err != nil {
			return nil, FetchOut{}, err
		}
		out, err := Fetch(ctx, a, agentID, in)
		return nil, out, err
	})
	return server
}

func principal(req *mcp.CallToolRequest) (string, error) {
	if req == nil || req.Extra == nil || req.Extra.TokenInfo == nil {
		return "", fmt.Errorf("mcp: unauthorized")
	}
	id := strings.TrimSpace(req.Extra.TokenInfo.UserID)
	if id == "" {
		return "", fmt.Errorf("mcp: unauthorized")
	}
	return id, nil
}

func Fetch(ctx context.Context, a *app.App, agentID string, in FetchIn) (FetchOut, error) {
	h := http.Header{}
	for k, v := range in.Headers {
		h.Add(k, v)
	}
	got, err := a.UseFetch(ctx, agentID, in.Item, protocol.Fetch{
		Method: in.Method,
		URL:    in.URL,
		Header: h,
		Body:   []byte(in.Body),
	})
	if err != nil {
		return FetchOut{}, err
	}
	out := FetchOut{Decision: string(got.Decision), Reason: got.Reason}
	if got.Fetch != nil {
		out.Status = got.Fetch.Status
		out.Body = string(got.Fetch.Body)
	}
	return out, nil
}
