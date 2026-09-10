// Package oidchttp is the HTTP client go-oidc uses for discovery and JWKS.
// Cloudflare Bot Fight 1010s the Go default User-Agent. We send ours.
package oidchttp

import (
	"context"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const ua = "password-manager"

type transport struct {
	base http.RoundTripper
}

func (t transport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("User-Agent", ua)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r)
}

func Context(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport{},
	})
}
