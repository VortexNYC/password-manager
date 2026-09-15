package proxy

import (
	"net/http"
	"strings"

	"github.com/vortexnyc/password-manager/internal/broker"
	"github.com/vortexnyc/password-manager/internal/grant"
	"github.com/vortexnyc/password-manager/internal/protocol"
)

// DummySecret is the Infisical-style placeholder in a child env. Origin run
// never copies vault material onto the laptop. HTTPS_PROXY substitutes.
const DummySecret = "veil-inject"

// wellKnownEnv is host → tool env names. Item name still becomes EnvName.
var wellKnownEnv = map[string][]string{
	"api.cloudflare.com": {"CLOUDFLARE_API_TOKEN"},
	"api.github.com":     {"GH_TOKEN", "GITHUB_TOKEN"},
	"api.linear.app":     {"LINEAR_API_KEY"},
	"api.stripe.com":     {"STRIPE_API_KEY", "STRIPE_SECRET_KEY"},
	"api.firecrawl.dev":  {"FIRECRAWL_API_KEY"},
	"api.resend.com":     {"RESEND_API_KEY"},
}

// DummyEnv is origin vault-run env: placeholders, never secrets.
func DummyEnv(items []protocol.Item) []string {
	seen := map[string]bool{}
	var out []string
	add := func(key string) {
		key = strings.TrimSpace(key)
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, key+"="+DummySecret)
	}
	for _, item := range items {
		if item.Archived || !item.Kind.Injects() {
			continue
		}
		add(broker.EnvName(item.Name))
		for _, raw := range item.URIs {
			u, err := grant.ParseDest(raw)
			if err != nil {
				continue
			}
			for _, alias := range wellKnownEnv[grant.CanonicalHost(u)] {
				add(alias)
			}
		}
	}
	return out
}

func dummyValue(v string) bool {
	return strings.Contains(v, DummySecret)
}

func originShouldUse(req *http.Request) bool {
	if req == nil {
		return false
	}
	auth := req.Header.Get("Authorization")
	if auth == "" {
		return true
	}
	if dummyValue(auth) {
		return true
	}
	for _, vs := range req.Header {
		for _, v := range vs {
			if dummyValue(v) {
				return true
			}
		}
	}
	return false
}
