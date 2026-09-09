// Package broker is the only path that ever sees a secret.
//
// Stolen from Infisical Agent Vault: the agent calls the real URL (or asks
// us to); we attach the credential at the edge and return the upstream
// result. The agent-visible UseResult is scrubbed.
package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/vortexnyc/password-manager/internal/grant"
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
	now := b.now()
	item, err := b.Store.Item(req.ItemID)
	if err != nil {
		return protocol.UseResult{Decision: protocol.DecisionDeny, Reason: "item_not_found"}, nil
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
	defer func() { b.Store.AppendAudit(event) }()

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
	fr, err := b.fetch(ctx, req.Fetch, secret)
	if err != nil {
		dec = protocol.UseResult{Decision: protocol.DecisionDeny, Reason: "fetch_failed"}
		event.Decision = dec.Decision
		event.Reason = dec.Reason
		return dec, err
	}
	fr.Body = scrub.Bytes(fr.Body, secret)
	for k, vs := range fr.Header {
		cleaned := make([]string, len(vs))
		for i, v := range vs {
			cleaned[i] = string(scrub.Bytes([]byte(v), secret))
		}
		fr.Header[k] = cleaned
	}
	dec.Fetch = fr
	return dec, nil
}

func (b *Broker) fetch(ctx context.Context, f *protocol.Fetch, secret store.Secret) (*protocol.FetchResult, error) {
	method := f.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if len(f.Body) > 0 {
		body = bytes.NewReader(f.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, f.URL, body)
	if err != nil {
		return nil, err
	}
	for k, vs := range f.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+string(secret))
	}
	res, err := b.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return &protocol.FetchResult{
		Status: res.StatusCode,
		Header: res.Header.Clone(),
		Body:   raw,
	}, nil
}

// Approve records a human approval for a level-1 grant.
func (b *Broker) Approve(human protocol.Principal, grantID string, ttl time.Duration) (protocol.Approval, error) {
	if human.Kind != protocol.PrincipalHuman {
		return protocol.Approval{}, store.ErrDenied
	}
	if _, err := b.Store.Human(human.ID); err != nil {
		return protocol.Approval{}, err
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
	return a, nil
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
