// Package mcpserver is the agent surface.
//
// Official SDK: github.com/modelcontextprotocol/go-sdk/mcp
// Source: https://github.com/modelcontextprotocol/go-sdk (v1.7.0)
//
// The process is bound to one agent (PWM_AGENT). The model cannot pick a
// different principal. Tools return Use results, never secrets.
package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/protocol"
)

type FetchIn struct {
	Item   string `json:"item" jsonschema:"item name the agent is granted"`
	URL    string `json:"url" jsonschema:"URL to fetch; host must match the item"`
	Method string `json:"method,omitempty" jsonschema:"HTTP method, default GET"`
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

func New(a *app.App, agentID string) (*mcp.Server, error) {
	if _, err := a.Store.Agent(agentID); err != nil {
		return nil, fmt.Errorf("mcp: unknown agent %q: %w", agentID, err)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "password-manager", Version: "0.0.1"}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_items",
		Description: "List items this agent may Use. Names and URIs only. Never secrets.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ListOut, error) {
		items, err := a.ItemsForAgent(agentID)
		if err != nil {
			return nil, ListOut{}, err
		}
		if items == nil {
			items = []protocol.Item{}
		}
		return nil, ListOut{Items: items}, nil
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "fetch",
		Description: "Call a URL as this agent. The broker injects the credential. You never receive the secret. Level-1 items return decision=need_approval until a human runs `password-manager approve`.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in FetchIn) (*mcp.CallToolResult, FetchOut, error) {
		out, err := Fetch(ctx, a, agentID, in)
		return nil, out, err
	})
	return server, nil
}

func Fetch(ctx context.Context, a *app.App, agentID string, in FetchIn) (FetchOut, error) {
	got, err := a.Use(ctx, agentID, in.Item, in.Method, in.URL)
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

func Run(ctx context.Context, a *app.App, agentID string) error {
	server, err := New(a, agentID)
	if err != nil {
		return err
	}
	return server.Run(ctx, &mcp.StdioTransport{})
}
