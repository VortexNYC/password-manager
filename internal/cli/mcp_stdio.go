package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vortexnyc/password-manager/internal/mcpserver"
	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/publicapi"
)

// originMCPServer is the laptop Cursor adapter. Same tools as origin MCP.
// Bearer is re-read from the token file on every call. Secrets never return.
func originMCPServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "veil", Version: "0.0.1"}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_items",
		Description: "List items this agent may Use. Names and URIs only. Never secrets.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, mcpserver.ListOut, error) {
		tok, err := originTokenLive(ctx, "")
		if err != nil {
			return nil, mcpserver.ListOut{}, err
		}
		raw, err := originDo(ctx, http.MethodGet, "/v1/items", tok, nil)
		if err != nil {
			return nil, mcpserver.ListOut{}, err
		}
		var out publicapi.ItemsResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, mcpserver.ListOut{}, err
		}
		if out.Items == nil {
			out.Items = []protocol.Item{}
		}
		return nil, mcpserver.ListOut{Items: out.Items}, nil
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "fetch",
		Description: "Call a URL as this agent. The broker injects the credential. You never receive the secret. Level-1 items return decision=need_approval until a human runs `password-manager approve`.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpserver.FetchIn) (*mcp.CallToolResult, mcpserver.FetchOut, error) {
		tok, err := originTokenLive(ctx, "")
		if err != nil {
			return nil, mcpserver.FetchOut{}, err
		}
		payload, err := json.Marshal(publicapi.UseRequest{
			Item:    in.Item,
			URL:     in.URL,
			Method:  in.Method,
			Headers: in.Headers,
			Body:    in.Body,
		})
		if err != nil {
			return nil, mcpserver.FetchOut{}, err
		}
		raw, err := originDo(ctx, http.MethodPost, "/v1/use", tok, payload)
		if err != nil {
			return nil, mcpserver.FetchOut{}, err
		}
		var got publicapi.UseResponse
		if err := json.Unmarshal(raw, &got); err != nil {
			return nil, mcpserver.FetchOut{}, err
		}
		return nil, mcpserver.FetchOut{
			Decision: string(got.Decision),
			Reason:   got.Reason,
			Status:   got.Status,
			Body:     got.Body,
		}, nil
	})
	return server
}

func runOriginMCPStdio(ctx context.Context) error {
	if originBase() == "" {
		return fmt.Errorf("mcp stdio: PWM_ORIGIN is required")
	}
	if _, err := originTokenLive(ctx, ""); err != nil {
		return err
	}
	return originMCPServer().Run(ctx, &mcp.StdioTransport{})
}
