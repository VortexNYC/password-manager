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
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/VortexNYC/veil/internal/app"
	"github.com/VortexNYC/veil/internal/protocol"
)

type FetchIn struct {
	Item    string            `json:"item" jsonschema:"item name the agent is granted"`
	URL     string            `json:"url" jsonschema:"URL to fetch; host must match the item"`
	Method  string            `json:"method,omitempty" jsonschema:"HTTP method, default GET"`
	Headers map[string]string `json:"headers,omitempty" jsonschema:"extra request headers. never the vault secret"`
	Body    string            `json:"body,omitempty" jsonschema:"request body. never the vault secret"`
	BodyB64 string            `json:"body_b64,omitempty" jsonschema:"base64 request body for binary payloads. never the vault secret"`
}

type FetchOut struct {
	Decision string      `json:"decision"`
	Reason   string      `json:"reason,omitempty"`
	Status   int         `json:"status,omitempty"`
	Headers  http.Header `json:"headers,omitempty"`
	Body     string      `json:"body,omitempty"`
	BodyB64  string      `json:"body_b64,omitempty"`
}

type ListOut struct {
	Items []protocol.Item `json:"items"`
}

func New(a *app.App) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "veil", Version: "0.0.1"}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_items",
		Description: "List items this agent may Use. Names, URIs, login. Never secrets.",
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
		Description: "Call a URL as this agent. The broker injects the credential. You never receive the secret. Level-1 items return decision=need_approval until a human runs `veil approve`.",
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
	if in.Body != "" && in.BodyB64 != "" {
		return FetchOut{}, fmt.Errorf("fetch: body and body_b64 are mutually exclusive")
	}
	body := []byte(in.Body)
	if in.BodyB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(in.BodyB64)
		if err != nil {
			return FetchOut{}, fmt.Errorf("fetch: bad body_b64: %w", err)
		}
		body = decoded
	}
	got, err := a.UseFetch(ctx, agentID, in.Item, protocol.Fetch{
		Method: in.Method,
		URL:    in.URL,
		Header: h,
		Body:   body,
	})
	if err != nil {
		return FetchOut{}, err
	}
	out := FetchOut{Decision: string(got.Decision), Reason: got.Reason}
	if got.Fetch != nil {
		out.Status = got.Fetch.Status
		out.Headers = got.Fetch.Header
		if utf8.Valid(got.Fetch.Body) {
			out.Body = string(got.Fetch.Body)
		} else {
			out.BodyB64 = base64.StdEncoding.EncodeToString(got.Fetch.Body)
		}
	}
	return out, nil
}
