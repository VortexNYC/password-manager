package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/vortexnyc/password-manager/internal/grant"
	"github.com/vortexnyc/password-manager/internal/protocol"
)

// OriginResult is POST /v1/use unwrapped for MITM. Not a GetSecret.
type OriginResult struct {
	Decision protocol.Decision
	Reason   string
	Status   int
	Body     string
}

// OriginUse fetches via origin. The laptop never receives the vault secret.
type OriginUse func(ctx context.Context, item, method, rawURL string, header http.Header, body []byte) (OriginResult, error)

// NewOrigin is HTTPS_PROXY against PWM_ORIGIN. Dummy env lives in DummyEnv.
func NewOrigin(agentID, dir string, items []protocol.Item, use OriginUse) (*Server, error) {
	if use == nil {
		return nil, fmt.Errorf("proxy: origin use is required")
	}
	ca, pemBytes, err := LoadOrCreateCA(dir)
	if err != nil {
		return nil, err
	}
	tok, err := newToken()
	if err != nil {
		return nil, err
	}
	return &Server{
		Agent:       protocol.Principal{Kind: protocol.PrincipalAgent, ID: agentID},
		Token:       tok,
		Dir:         dir,
		CA:          ca,
		CAPEM:       pemBytes,
		ListenAddr:  "127.0.0.1:0",
		Now:         time.Now,
		OriginItems: items,
		OriginUse:   use,
	}, nil
}

func (s *Server) originItem(raw string) (protocol.Item, protocol.UseResult) {
	n := 0
	var hit protocol.Item
	for _, item := range s.OriginItems {
		if item.Archived {
			continue
		}
		if !grant.HostAllowed(item, raw) {
			continue
		}
		n++
		hit = item
	}
	if n == 0 {
		return protocol.Item{}, protocol.UseResult{Decision: protocol.DecisionDeny, Reason: "host_not_allowed"}
	}
	if n > 1 {
		return protocol.Item{}, protocol.UseResult{Decision: protocol.DecisionDeny, Reason: "ambiguous_item"}
	}
	return hit, protocol.UseResult{Decision: protocol.DecisionAllow}
}

func (s *Server) injectOrigin(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	raw := destURL(req)
	item, dec := s.originItem(raw)
	if dec.Decision != protocol.DecisionAllow {
		return nil, jsonResp(req, http.StatusForbidden, dec)
	}
	if !originShouldUse(req) {
		return req, nil
	}
	hdr := http.Header{}
	for k, vs := range req.Header {
		if strings.EqualFold(k, "Proxy-Authorization") || strings.EqualFold(k, "Proxy-Connection") {
			continue
		}
		for _, v := range vs {
			if dummyValue(v) {
				continue
			}
			hdr.Add(k, v)
		}
	}
	var body []byte
	if req.Body != nil {
		rawBody, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		_ = req.Body.Close()
		if err != nil {
			return nil, jsonResp(req, http.StatusInternalServerError, protocol.UseResult{
				Decision: protocol.DecisionDeny,
				Reason:   "lookup_failed",
			})
		}
		body = rawBody
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	out, err := s.OriginUse(req.Context(), item.Name, method, raw, hdr, body)
	if err != nil {
		return nil, jsonResp(req, http.StatusInternalServerError, protocol.UseResult{
			Decision: protocol.DecisionDeny,
			Reason:   "lookup_failed",
		})
	}
	if ctx != nil {
		data, _ := ctx.UserData.(ctxData)
		data.authed = true
		ctx.UserData = data
	}
	return nil, originHTTP(req, out)
}

func originHTTP(req *http.Request, out OriginResult) *http.Response {
	if out.Decision != protocol.DecisionAllow {
		return jsonResp(req, http.StatusForbidden, protocol.UseResult{Decision: out.Decision, Reason: out.Reason})
	}
	status := out.Status
	if status == 0 {
		status = http.StatusOK
	}
	body := []byte(out.Body)
	h := http.Header{}
	if len(body) > 0 && body[0] != '{' && body[0] != '[' {
		h.Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		h.Set("Content-Type", "application/json")
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	return &http.Response{
		StatusCode:    status,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        h,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}
