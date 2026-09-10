// Package publicapi is the HTTP projection of the OpenAPI contract.
//
// Same Bearer as MCP. Responses never include vault secrets. CLI, MCP, and
// generated SDKs are adapters over these operations.
package publicapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/protocol"
)

type UseRequest struct {
	Item    string            `json:"item"`
	URL     string            `json:"url"`
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

type UseResponse struct {
	Decision   protocol.Decision `json:"decision"`
	Reason     string            `json:"reason,omitempty"`
	ApprovalID string            `json:"approval_id,omitempty"`
	Status     int               `json:"status,omitempty"`
	Body       string            `json:"body,omitempty"`
}

type ItemsResponse struct {
	Items []protocol.Item `json:"items"`
}

func Mount(mux *http.ServeMux, a *app.App) {
	mux.HandleFunc("GET /openapi.json", spec)
	mux.HandleFunc("GET /v1/items", func(w http.ResponseWriter, r *http.Request) {
		p, ok := requireAgent(w, r, a)
		if !ok {
			return
		}
		items, err := a.ItemsForAgent(p.ID)
		if err != nil {
			http.Error(w, "list failed", http.StatusBadRequest)
			return
		}
		if items == nil {
			items = []protocol.Item{}
		}
		writeJSON(w, ItemsResponse{Items: items})
	})
	mux.HandleFunc("POST /v1/use", func(w http.ResponseWriter, r *http.Request) {
		p, ok := requireAgent(w, r, a)
		if !ok {
			return
		}
		var in UseRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if in.Item == "" || in.URL == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		h := http.Header{}
		for k, v := range in.Headers {
			h.Add(k, v)
		}
		got, err := a.UseFetch(r.Context(), p.ID, in.Item, protocol.Fetch{
			Method: in.Method,
			URL:    in.URL,
			Header: h,
			Body:   []byte(in.Body),
		})
		if err != nil {
			http.Error(w, "use failed", http.StatusBadRequest)
			return
		}
		out := UseResponse{Decision: got.Decision, Reason: got.Reason, ApprovalID: got.ApprovalID}
		if got.Fetch != nil {
			out.Status = got.Fetch.Status
			out.Body = string(got.Fetch.Body)
		}
		writeJSON(w, out)
	})
}

func requireAgent(w http.ResponseWriter, r *http.Request, a *app.App) (protocol.Principal, bool) {
	raw := bearer(r.Header.Get("Authorization"))
	p, err := a.AgentFromOIDC(r.Context(), raw)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return protocol.Principal{}, false
	}
	return p, true
}

func bearer(h string) string {
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		return ""
	}
	return strings.TrimSpace(h[len(p):])
}

func writeJSON[T ItemsResponse | UseResponse](w http.ResponseWriter, v T) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func spec(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(Spec)
}
