// Package socket is the laptop transport. Same agent credential as cloud.
// Not a new identity. Stdlib HTTP on a unix socket, same idea as docker.sock.
package socket

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/protocol"
)

const Name = "pwm.sock"

type Server struct {
	Path string
	app  *app.App
	ln   net.Listener
	srv  *http.Server
}

func DefaultPath(home string) string {
	return filepath.Join(home, Name)
}

func Listen(a *app.App, path string) (*Server, error) {
	if path == "" {
		path = DefaultPath(a.Dir)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := removeStale(path); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, err
	}
	s := &Server{Path: path, app: a, ln: ln}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /use", s.handle(s.use))
	mux.HandleFunc("GET /items", s.handle(s.items))
	s.srv = &http.Server{Handler: mux}
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	var err error
	if s.srv != nil {
		err = s.srv.Close()
	}
	if s.ln != nil {
		_ = s.ln.Close()
	}
	if s.Path != "" {
		_ = os.Remove(s.Path)
	}
	return err
}

type useIn struct {
	Item    string            `json:"item"`
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

type useOut struct {
	Decision   protocol.Decision `json:"decision"`
	Reason     string            `json:"reason,omitempty"`
	ApprovalID string            `json:"approval_id,omitempty"`
	Status     int               `json:"status,omitempty"`
	Body       string            `json:"body,omitempty"`
}

type itemsOut struct {
	Items []protocol.Item `json:"items"`
}

func (s *Server) handle(fn func(http.ResponseWriter, *http.Request, protocol.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agent, err := s.app.AgentFromOIDC(r.Context(), bearer(r.Header.Get("Authorization")))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		fn(w, r, agent)
	}
}

func (s *Server) use(w http.ResponseWriter, r *http.Request, agent protocol.Principal) {
	var in useIn
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
	got, err := s.app.UseFetch(r.Context(), agent.ID, in.Item, protocol.Fetch{
		Method: in.Method,
		URL:    in.URL,
		Header: h,
		Body:   []byte(in.Body),
	})
	if err != nil {
		http.Error(w, "use failed", http.StatusBadRequest)
		return
	}
	out := useOut{Decision: got.Decision, Reason: got.Reason, ApprovalID: got.ApprovalID}
	if got.Fetch != nil {
		out.Status = got.Fetch.Status
		out.Body = string(got.Fetch.Body)
	}
	writeJSON(w, out)
}

func (s *Server) items(w http.ResponseWriter, r *http.Request, agent protocol.Principal) {
	items, err := s.app.ItemsForAgent(agent.ID)
	if err != nil {
		http.Error(w, "list failed", http.StatusBadRequest)
		return
	}
	if items == nil {
		items = []protocol.Item{}
	}
	writeJSON(w, itemsOut{Items: items})
}

func bearer(h string) string {
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		return ""
	}
	return strings.TrimSpace(h[len(p):])
}

func writeJSON[T useOut | itemsOut](w http.ResponseWriter, v T) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func removeStale(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("socket: %s exists and is not a socket", path)
	}
	return os.Remove(path)
}
