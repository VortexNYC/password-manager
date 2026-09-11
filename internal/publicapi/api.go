// Package publicapi is the HTTP projection of the OpenAPI contract.
//
// Same Bearer as MCP. Responses never include vault secrets. CLI, MCP, and
// generated SDKs are adapters over these operations.
//
// POST /v1/fill/* is the native-host secret path. It is not on the OpenAPI
// contract and not an MCP tool.
package publicapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

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

type EventsResponse struct {
	Events []protocol.AuditEvent `json:"events"`
}

type CreateItemRequest struct {
	Name     string   `json:"name"`
	URI      string   `json:"uri,omitempty"`
	URIs     []string `json:"uris,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Kind     string   `json:"kind,omitempty"`
	Secret   string   `json:"secret,omitempty"`
	TOTPSeed string   `json:"totp_seed,omitempty"`
	Login    string   `json:"login,omitempty"`
}

type UpdateItemRequest struct {
	URI   string   `json:"uri,omitempty"`
	URIs  []string `json:"uris,omitempty"`
	Tags  []string `json:"tags,omitempty"`
	Login string   `json:"login,omitempty"`
}

type CreateGrantRequest struct {
	Agent   string `json:"agent,omitempty"`
	Human   string `json:"human,omitempty"`
	Item    string `json:"item"`
	Level   string `json:"level"`
	Expires string `json:"expires,omitempty"`
}

type GrantView struct {
	ID        string     `json:"id"`
	OrgID     string     `json:"org_id"`
	AgentID   string     `json:"agent_id"`
	ItemID    string     `json:"item_id"`
	Level     string     `json:"level"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type GrantsResponse struct {
	Grants []GrantView `json:"grants"`
}

type FillLoginsRequest struct {
	URL string `json:"url"`
}

type FillLogin struct {
	Login    string `json:"login"`
	Name     string `json:"name"`
	Password string `json:"password"`
	UUID     string `json:"uuid"`
}

type FillLoginsResponse struct {
	Entries []FillLogin `json:"entries"`
}

type FillTOTPRequest struct {
	UUID string `json:"uuid"`
}

type FillTOTPResponse struct {
	TOTP string `json:"totp"`
}

type Server struct {
	App      *app.App
	Identity func(ctx context.Context, token string) (protocol.Principal, error)
}

func Mount(mux *http.ServeMux, a *app.App) {
	(&Server{App: a}).Mount(mux)
}

func (s *Server) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /openapi.json", spec)
	mux.HandleFunc("GET /v1/items", s.listItems)
	mux.HandleFunc("POST /v1/items", s.createItem)
	mux.HandleFunc("PATCH /v1/items/{name}", s.updateItem)
	mux.HandleFunc("POST /v1/items/{name}/archive", s.archiveItem)
	mux.HandleFunc("DELETE /v1/items/{name}", s.deleteItem)
	mux.HandleFunc("GET /v1/grants", s.listGrants)
	mux.HandleFunc("POST /v1/grants", s.createGrant)
	mux.HandleFunc("POST /v1/use", s.useItem)
	mux.HandleFunc("GET /v1/events", s.listEvents)
	mux.HandleFunc("POST /v1/fill/logins", s.fillLogins)
	mux.HandleFunc("POST /v1/fill/totp", s.fillTOTP)
}

func (s *Server) listItems(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	items, err := s.App.ItemsForPrincipal(p)
	if err != nil {
		http.Error(w, "list failed", http.StatusBadRequest)
		return
	}
	if items == nil {
		items = []protocol.Item{}
	}
	writeJSON(w, ItemsResponse{Items: items})
}

func (s *Server) createItem(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireHuman(w, r); !ok {
		return
	}
	var in CreateItemRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	item, err := s.App.PutItem(app.ItemOpts{
		Name:     in.Name,
		URI:      in.URI,
		URIs:     in.URIs,
		Tags:     in.Tags,
		Kind:     protocol.ItemKind(in.Kind),
		Token:    []byte(in.Secret),
		Login:    in.Login,
		TOTPSeed: []byte(in.TOTPSeed),
	})
	if err != nil {
		http.Error(w, "create failed", http.StatusBadRequest)
		return
	}
	writeJSON(w, item)
}

func (s *Server) updateItem(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireHuman(w, r); !ok {
		return
	}
	var in UpdateItemRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	uris := in.URIs
	if in.URI != "" {
		uris = []string{in.URI}
	}
	item, err := s.App.UpdateItem(r.PathValue("name"), uris, in.Tags, in.Login)
	if err != nil {
		http.Error(w, "update failed", http.StatusBadRequest)
		return
	}
	writeJSON(w, item)
}

func (s *Server) archiveItem(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireHuman(w, r); !ok {
		return
	}
	if err := s.App.ArchiveItem(r.PathValue("name")); err != nil {
		http.Error(w, "archive failed", http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]bool{"archived": true})
}

func (s *Server) deleteItem(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireHuman(w, r); !ok {
		return
	}
	if err := s.App.DeleteItem(r.PathValue("name")); err != nil {
		http.Error(w, "delete failed", http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]bool{"deleted": true})
}

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireHuman(w, r); !ok {
		return
	}
	grants, err := s.App.Store.ListGrants()
	if err != nil {
		http.Error(w, "list failed", http.StatusBadRequest)
		return
	}
	out := make([]GrantView, 0, len(grants))
	for _, g := range grants {
		out = append(out, grantView(g))
	}
	writeJSON(w, GrantsResponse{Grants: out})
}

func (s *Server) createGrant(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireHuman(w, r)
	if !ok {
		return
	}
	ok, err := s.App.CanCreateGrant(p)
	if err != nil || !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var in CreateGrantRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if strings.Contains(in.Human, "@") {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	grantee := strings.TrimSpace(in.Agent)
	human := strings.TrimSpace(in.Human)
	switch {
	case grantee != "" && human != "":
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	case human != "":
		grantee = human
	case grantee == "":
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var until *time.Time
	if in.Expires != "" {
		d, err := time.ParseDuration(in.Expires)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		t := time.Now().Add(d)
		until = &t
	}
	g, err := s.App.GrantUntil(grantee, in.Item, protocol.GrantLevel(in.Level), until)
	if err != nil {
		http.Error(w, "grant failed", http.StatusBadRequest)
		return
	}
	writeJSON(w, grantView(g))
}

func (s *Server) useItem(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAgent(w, r)
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
	got, err := s.App.UseFetch(r.Context(), p.ID, in.Item, protocol.Fetch{
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
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	all, err := s.App.Store.Audit()
	if err != nil {
		http.Error(w, "audit failed", http.StatusBadRequest)
		return
	}
	mine := make([]protocol.AuditEvent, 0, len(all))
	for _, e := range all {
		if p.Kind == protocol.PrincipalHuman || e.AgentID == p.ID {
			mine = append(mine, e)
		}
	}
	if n := len(mine); n > 100 {
		mine = mine[n-100:]
	}
	writeJSON(w, EventsResponse{Events: mine})
}

func (s *Server) fillLogins(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireHuman(w, r)
	if !ok {
		return
	}
	var in FillLoginsRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	got, err := s.App.FillLogins(p, in.URL)
	if err != nil {
		http.Error(w, "fill failed", http.StatusBadRequest)
		return
	}
	entries := make([]FillLogin, 0, len(got))
	for _, e := range got {
		entries = append(entries, FillLogin{Login: e.Login, Name: e.Name, Password: e.Password, UUID: e.UUID})
	}
	writeJSON(w, FillLoginsResponse{Entries: entries})
}

func (s *Server) fillTOTP(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireHuman(w, r)
	if !ok {
		return
	}
	var in FillTOTPRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	code, err := s.App.FillTOTP(p, in.UUID, time.Now())
	if err != nil {
		http.Error(w, "fill failed", http.StatusBadRequest)
		return
	}
	writeJSON(w, FillTOTPResponse{TOTP: code})
}

func (s *Server) resolve(r *http.Request) (protocol.Principal, error) {
	raw := bearer(r.Header.Get("Authorization"))
	if s.Identity != nil {
		return s.Identity(r.Context(), raw)
	}
	return s.App.PrincipalFromOIDC(r.Context(), raw)
}

func (s *Server) requirePrincipal(w http.ResponseWriter, r *http.Request) (protocol.Principal, bool) {
	p, err := s.resolve(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return protocol.Principal{}, false
	}
	return p, true
}

func (s *Server) requireAgent(w http.ResponseWriter, r *http.Request) (protocol.Principal, bool) {
	p, ok := s.requirePrincipal(w, r)
	if !ok {
		return protocol.Principal{}, false
	}
	if p.Kind != protocol.PrincipalAgent {
		http.Error(w, "forbidden", http.StatusForbidden)
		return protocol.Principal{}, false
	}
	return p, true
}

func (s *Server) requireHuman(w http.ResponseWriter, r *http.Request) (protocol.Principal, bool) {
	p, ok := s.requirePrincipal(w, r)
	if !ok {
		return protocol.Principal{}, false
	}
	if p.Kind != protocol.PrincipalHuman {
		http.Error(w, "forbidden", http.StatusForbidden)
		return protocol.Principal{}, false
	}
	return p, true
}

func grantView(g protocol.Grant) GrantView {
	return GrantView{
		ID:        g.ID,
		OrgID:     g.OrgID,
		AgentID:   g.AgentID,
		ItemID:    g.ItemID,
		Level:     string(g.Level),
		ExpiresAt: g.ExpiresAt,
	}
}

func bearer(h string) string {
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		return ""
	}
	return strings.TrimSpace(h[len(p):])
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func spec(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(Spec)
}
