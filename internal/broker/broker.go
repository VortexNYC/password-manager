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
	"errors"
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
	"golang.org/x/sync/semaphore"

	"github.com/veilnyc/password-manager/internal/audit"
	"github.com/veilnyc/password-manager/internal/grant"
	"github.com/veilnyc/password-manager/internal/material"
	"github.com/veilnyc/password-manager/internal/protocol"
	"github.com/veilnyc/password-manager/internal/scrub"
	"github.com/veilnyc/password-manager/internal/store"
)

var (
	ErrOverloaded  = errors.New("broker: origin overloaded")
	ErrUnauthorized = errors.New("broker: unauthorized")
)

const defaultAuditTimeout = 500 * time.Millisecond

type Clock func() time.Time

type Broker struct {
	Store        store.Store
	Auditor      audit.Auditor
	AuditTimeout time.Duration
	HTTP         *http.Client
	Now          Clock
	useLimit     *semaphore.Weighted
}

func New(s store.Store) *Broker {
	return newBroker(s, nil, 0)
}

// NewWithInFlight creates a Broker that allows at most n concurrent Use calls.
// n <= 0 means unlimited.
func NewWithInFlight(s store.Store, n int) *Broker {
	return newBroker(s, nil, n)
}

func newBroker(s store.Store, a audit.Auditor, inFlight int) *Broker {
	// Clone the default transport so outbound connections to the same upstream
	// are reused instead of churned. The default MaxIdleConnsPerHost is only 2.
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 100
	t.MaxIdleConnsPerHost = 100
	if a == nil {
		a = &audit.Sync{Store: s}
	}
	b := &Broker{
		Store:        s,
		Auditor:      a,
		AuditTimeout: defaultAuditTimeout,
		Now:          time.Now,
		HTTP: &http.Client{
			Timeout:   15 * time.Second,
			Transport: t,
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
	if inFlight > 0 {
		b.useLimit = semaphore.NewWeighted(int64(inFlight))
	}
	return b
}

func (b *Broker) now() time.Time {
	if b.Now == nil {
		return time.Now()
	}
	return b.Now()
}

func (b *Broker) appendAudit(ctx context.Context, e protocol.AuditEvent) {
	timeout := b.AuditTimeout
	if timeout <= 0 {
		timeout = defaultAuditTimeout
	}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	if err := b.Auditor.Append(auditCtx, e); err != nil {
		if audit.IsDropped(err) {
			slog.Warn("audit event dropped", "error", err, "agent", e.AgentID, "item", e.ItemID)
		} else {
			slog.Error("audit append failed", "error", err, "agent", e.AgentID, "item", e.ItemID)
		}
	}
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

	// Admission: bound in-flight Use calls so a flood cannot hold unlimited
	// goroutines and upstream connections.
	if b.useLimit != nil {
		if !b.useLimit.TryAcquire(1) {
			span.SetStatus(codes.Error, "origin_overload")
			return protocol.UseResult{}, ErrOverloaded
		}
		defer b.useLimit.Release(1)
	}

	auth, err := b.Store.UseAuth(agent.ID, req.ItemID, now)
	if err != nil {
		return protocol.UseResult{}, err
	}
	return b.useAuthorized(ctx, span, agent, req, auth, nil, now)
}

func (b *Broker) UseSession(ctx context.Context, sessionHash []byte, req protocol.UseRequest) (protocol.UseResult, error) {
	ctx, span := otel.Tracer("veil").Start(ctx, "use")
	defer span.End()
	now := b.now()

	if b.useLimit != nil {
		if !b.useLimit.TryAcquire(1) {
			span.SetStatus(codes.Error, "origin_overload")
			return protocol.UseResult{}, ErrOverloaded
		}
		defer b.useLimit.Release(1)
	}

	auth, err := b.Store.UseAuthSession(sessionHash, req.ItemID, now)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrSessionExpired) || errors.Is(err, store.ErrSessionRevoked) || errors.Is(err, store.ErrDenied) {
			return protocol.UseResult{}, ErrUnauthorized
		}
		return protocol.UseResult{}, err
	}
	if auth.Agent.ID == "" {
		return protocol.UseResult{}, ErrUnauthorized
	}
	return b.useAuthorized(ctx, span, auth.Agent, req, auth, sessionHash, now)
}

func (b *Broker) useAuthorized(ctx context.Context, span trace.Span, agent protocol.Principal, req protocol.UseRequest, auth store.UseAuth, sessionHash []byte, now time.Time) (protocol.UseResult, error) {
	// Tests may pass a bare principal with no store entry; do not fail those.
	// A real store error fails closed above. Unknown agents fall through to
	// grant evaluation, which will deny as no_grant.
	if auth.Agent.ID != "" {
		agent = auth.Agent
	}

	if auth.Item.ID == "" {
		dec := protocol.UseResult{Decision: protocol.DecisionDeny, Reason: "item_not_found"}
		evt := protocol.AuditEvent{
			Time: now, OrgID: agent.OrgID, AgentID: agent.ID, ItemID: req.ItemID,
			Action: req.Action, Decision: dec.Decision, Reason: dec.Reason,
		}
		b.appendAudit(ctx, evt)
		LogEvent(evt, req.ItemID, "", 0)
		spanUse(span, agent.ID, req.ItemID, dec, 0, "")
		return dec, nil
	}

	item := auth.Item
	target := ""
	if req.Fetch != nil {
		target = req.Fetch.URL
	}
	dec := grant.Evaluate(grant.Input{
		Principal: agent,
		Item:      item,
		Grant:     auth.Grant,
		Action:    req.Action,
		TargetURL: target,
		Approval:  auth.Approval,
		Now:       now,
	})

	// For agent-token Use calls, reload the agent immediately before touching
	// the secret to catch a revocation that happened during grant/approval
	// lookups. For session-token calls, ConsumeSession below provides the same
	// final revocation check and consumes the session use atomically.
	if sessionHash == nil {
		if current, err := b.Store.Agent(agent.ID); err == nil {
			agent = current
		} else if !errors.Is(err, store.ErrNotFound) {
			return protocol.UseResult{}, err
		}
		if agent.RevokedAt != nil {
			dec = protocol.UseResult{Decision: protocol.DecisionDeny, Reason: "agent_revoked"}
		}
	}

	if dec.Decision != protocol.DecisionAllow {
		return b.auditUse(ctx, span, agent, item, req, dec, target, 0, now), nil
	}
	if !item.Kind.Injects() {
		dec = protocol.UseResult{Decision: protocol.DecisionDeny, Reason: "not_injectable"}
		return b.auditUse(ctx, span, agent, item, req, dec, target, 0, now), nil
	}
	if req.Action != protocol.ActionFetch || req.Fetch == nil {
		dec = protocol.UseResult{Decision: protocol.DecisionDeny, Reason: "unsupported_action"}
		return b.auditUse(ctx, span, agent, item, req, dec, target, 0, now), nil
	}

	if sessionHash != nil {
		current, err := b.Store.ConsumeSession(sessionHash, now)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrSessionExpired) || errors.Is(err, store.ErrSessionRevoked) || errors.Is(err, store.ErrDenied) {
				dec = protocol.UseResult{Decision: protocol.DecisionDeny, Reason: "session_revoked"}
				return b.auditUse(ctx, span, agent, item, req, dec, target, 0, now), nil
			}
			return protocol.UseResult{}, err
		}
		agent = current
	}

	secret, err := b.Store.Secret(item.ID)
	if err != nil {
		return protocol.UseResult{}, err
	}
	env := material.Unpack(secret)
	fr, code, access, err := b.fetch(ctx, req.Fetch, env, now)
	if err != nil {
		dec = protocol.UseResult{Decision: protocol.DecisionDeny, Reason: "fetch_failed"}
		return b.auditUse(ctx, span, agent, item, req, dec, target, 0, now), err
	}
	status := fr.Status
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
	return b.auditUse(ctx, span, agent, item, req, dec, target, status, now), nil
}

func (b *Broker) auditUse(ctx context.Context, span trace.Span, agent protocol.Principal, item protocol.Item, req protocol.UseRequest, dec protocol.UseResult, target string, status int, now time.Time) protocol.UseResult {
	host := hostPath(target)
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
	b.appendAudit(ctx, event)
	LogEvent(event, item.Name, host, status)
	spanUse(span, agent.ID, item.Name, dec, status, host)
	return dec
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
