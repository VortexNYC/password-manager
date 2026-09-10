// Package broker is the only path that ever sees a secret.
//
// Same inject-at-the-edge pattern as Infisical Agent Vault: the agent calls
// the real URL (or asks us to); we attach the credential at the edge and
// return the upstream result. The agent-visible UseResult is scrubbed.
package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/vortexnyc/password-manager/internal/grant"
	"github.com/vortexnyc/password-manager/internal/material"
	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/scrub"
	"github.com/vortexnyc/password-manager/internal/store"
)

type Clock func() time.Time

type Broker struct {
	Store store.Store
	HTTP  *http.Client
	Now   Clock
}

func New(s store.Store) *Broker {
	return &Broker{
		Store: s,
		Now:   time.Now,
		HTTP: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) == 0 {
					return nil
				}
				prev := via[len(via)-1].URL.Hostname()
				if req.URL.Hostname() != prev {
					req.Header.Del("Authorization")
					req.Header.Del(material.HeaderTOTP)
				}
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				return nil
			},
		},
	}
}

func (b *Broker) now() time.Time {
	if b.Now == nil {
		return time.Now()
	}
	return b.Now()
}

func (b *Broker) client() *http.Client {
	if b.HTTP != nil {
		return b.HTTP
	}
	return http.DefaultClient
}

// Use performs an action for an agent. It never puts a secret on UseResult.
func (b *Broker) Use(ctx context.Context, agent protocol.Principal, req protocol.UseRequest) (protocol.UseResult, error) {
	ctx, span := otel.Tracer("veil").Start(ctx, "use")
	defer span.End()
	now := b.now()
	item, err := b.Store.Item(req.ItemID)
	if err != nil {
		dec := protocol.UseResult{Decision: protocol.DecisionDeny, Reason: "item_not_found"}
		LogEvent(protocol.AuditEvent{
			Time: now, OrgID: agent.OrgID, AgentID: agent.ID, ItemID: req.ItemID,
			Action: req.Action, Decision: dec.Decision, Reason: dec.Reason,
		}, req.ItemID, "", 0)
		spanUse(span, agent.ID, req.ItemID, dec, 0, "")
		return dec, nil
	}
	g, err := b.Store.GrantFor(agent.ID, req.ItemID)
	if err != nil {
		return protocol.UseResult{}, err
	}
	target := ""
	if req.Fetch != nil {
		target = req.Fetch.URL
	}
	var appr *protocol.Approval
	if g != nil {
		appr, err = b.Store.LiveApproval(g.ID, now)
		if err != nil {
			return protocol.UseResult{}, err
		}
	}
	dec := grant.Evaluate(grant.Input{
		Principal: agent,
		Item:      item,
		Grant:     g,
		Action:    req.Action,
		TargetURL: target,
		Approval:  appr,
		Now:       now,
	})
	event := protocol.AuditEvent{
		Time:       now,
		OrgID:      agent.OrgID,
		AgentID:    agent.ID,
		ItemID:     req.ItemID,
		Action:     req.Action,
		Decision:   dec.Decision,
		Reason:     dec.Reason,
		ApprovalID: dec.ApprovalID,
	}
	host := hostPath(target)
	status := 0
	defer func() {
		_ = b.Store.AppendAudit(event)
		LogEvent(event, item.Name, host, status)
		spanUse(span, agent.ID, item.Name, dec, status, host)
	}()

	if dec.Decision != protocol.DecisionAllow {
		return dec, nil
	}
	if req.Action != protocol.ActionFetch || req.Fetch == nil {
		dec.Reason = "unsupported_action"
		dec.Decision = protocol.DecisionDeny
		event.Decision = dec.Decision
		event.Reason = dec.Reason
		return dec, nil
	}

	secret, err := b.Store.Secret(item.ID)
	if err != nil {
		return protocol.UseResult{}, err
	}
	env := material.Unpack(secret)
	fr, code, access, err := b.fetch(ctx, req.Fetch, env, now)
	if err != nil {
		dec = protocol.UseResult{Decision: protocol.DecisionDeny, Reason: "fetch_failed"}
		event.Decision = dec.Decision
		event.Reason = dec.Reason
		return dec, err
	}
	status = fr.Status
	hide := material.ScrubList(env, secret, []byte(code), []byte(access))
	fr.Body = scrub.Bytes(fr.Body, hide...)
	for k, vs := range fr.Header {
		cleaned := make([]string, len(vs))
		for i, v := range vs {
			cleaned[i] = string(scrub.Bytes([]byte(v), hide...))
		}
		fr.Header[k] = cleaned
	}
	dec.Fetch = fr
	return dec, nil
}

func (b *Broker) fetch(ctx context.Context, f *protocol.Fetch, env material.Envelope, now time.Time) (*protocol.FetchResult, string, string, error) {
	method := f.Method
	if method == "" {
		method = http.MethodGet
	}
	ctx, span := otel.Tracer("veil").Start(ctx, "upstream")
	defer span.End()
	span.SetAttributes(
		attribute.String("http.request.method", method),
		attribute.String("veil.host", hostPath(f.URL)),
	)
	var body io.Reader
	if len(f.Body) > 0 {
		body = bytes.NewReader(f.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, f.URL, body)
	if err != nil {
		return nil, "", "", err
	}
	for k, vs := range f.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	access, err := material.AccessToken(ctx, env, b.client())
	if err != nil {
		return nil, "", "", err
	}
	if access != "" && req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", material.AuthorizationValue(access))
	}
	code, err := material.Apply(req.Header, env, now)
	if err != nil {
		return nil, "", "", err
	}
	res, err := b.client().Do(req)
	if err != nil {
		span.SetStatus(codes.Error, "upstream")
		return nil, "", "", err
	}
	defer res.Body.Close()
	span.SetAttributes(attribute.Int("http.response.status_code", res.StatusCode))
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, "", "", err
	}
	return &protocol.FetchResult{
		Status: res.StatusCode,
		Header: res.Header.Clone(),
		Body:   raw,
	}, code, access, nil
}

// Approve records a human approval for a level-1 grant.
// Membership is Keto via App.ApproveOIDC. This store does not decide who is a human.
func (b *Broker) Approve(human protocol.Principal, grantID string, ttl time.Duration) (protocol.Approval, error) {
	if human.Kind != protocol.PrincipalHuman {
		return protocol.Approval{}, store.ErrDenied
	}
	a := protocol.Approval{
		ID:        fmt.Sprintf("appr-%d", b.now().UnixNano()),
		GrantID:   grantID,
		HumanID:   human.ID,
		ExpiresAt: b.now().Add(ttl),
	}
	if err := b.Store.PutApproval(a); err != nil {
		return protocol.Approval{}, err
	}
	slog.Info("approve", "human", human.ID, "grant", grantID)
	return a, nil
}

// LogEvent writes a grant event to slog. No secrets, no query string, no body.
// HTTP request logs are Railway (`railway logs --http`). This is the grant line.
func LogEvent(e protocol.AuditEvent, item, host string, status int) {
	attrs := []any{
		"agent", e.AgentID,
		"item", item,
		"action", string(e.Action),
		"decision", string(e.Decision),
	}
	if e.Reason != "" {
		attrs = append(attrs, "reason", e.Reason)
	}
	if host != "" {
		if h := hostPath(host); h != "" {
			host = h
		}
		attrs = append(attrs, "host", host)
	}
	if status > 0 {
		attrs = append(attrs, "status", status)
	}
	slog.Info("use", attrs...)
}

func hostPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + u.Path
}

func spanUse(span trace.Span, agent, item string, dec protocol.UseResult, status int, host string) {
	span.SetAttributes(
		attribute.String("veil.agent", agent),
		attribute.String("veil.item", item),
		attribute.String("veil.decision", string(dec.Decision)),
	)
	if dec.Reason != "" {
		span.SetAttributes(attribute.String("veil.reason", dec.Reason))
	}
	if host != "" {
		span.SetAttributes(attribute.String("veil.host", host))
	}
	if status > 0 {
		span.SetAttributes(attribute.Int("http.response.status_code", status))
	}
	if dec.Decision != protocol.DecisionAllow {
		span.SetStatus(codes.Error, dec.Reason)
	}
}

// AssertNoSecret marshals v and fails the test helper contract if secret appears.
func AssertNoSecret(v any, secret []byte) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if scrub.Contains(b, secret) {
		return fmt.Errorf("secret leaked in %s", b)
	}
	return nil
}
