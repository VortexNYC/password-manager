package mcpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/publicapi"
)

const (
	DefaultAddr      = "127.0.0.1:4461"
	DefaultPublicURL = "https://pwm.vortex.nyc/mcp"
	DefaultIssuer    = "https://id.vortex.nyc"
	Path             = "/mcp"
)

func ResourceURL(listen string) string {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		listen = DefaultAddr
	}
	return "http://" + listen + Path
}

func Handler(a *app.App, publicURL string) http.Handler {
	server := New(a)
	stream := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, &mcp.StreamableHTTPOptions{
		Stateless:                  true,
		DisableLocalhostProtection: publicHost(publicURL),
	})
	opts := &auth.RequireBearerTokenOptions{AllowMissingExpiration: true}
	if publicURL != "" {
		opts.ResourceMetadataURL = wellKnownURL(publicURL)
	}
	return auth.RequireBearerToken(func(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		agent, err := a.AgentFromOIDC(ctx, token)
		if err != nil {
			return nil, fmt.Errorf("%w", auth.ErrInvalidToken)
		}
		return &auth.TokenInfo{UserID: agent.ID, Scopes: []string{"mcp"}}, nil
	}, opts)(stream)
}

func Mux(a *app.App, publicURL, issuer string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	h := Handler(a, publicURL)
	mux.Handle(Path, h)
	mux.Handle(Path+"/", h)
	publicapi.Mount(mux, a)
	if publicURL != "" && issuer != "" {
		meta := &oauthex.ProtectedResourceMetadata{
			Resource:               publicURL,
			AuthorizationServers:   []string{issuer},
			BearerMethodsSupported: []string{"header"},
		}
		wellKnown := auth.ProtectedResourceMetadataHandler(meta)
		mux.Handle("/.well-known/oauth-protected-resource", wellKnown)
		mux.Handle("/.well-known/oauth-protected-resource/", wellKnown)
	}
	return mux
}

func publicHost(resourceURL string) bool {
	u, err := url.Parse(resourceURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host != "" && host != "127.0.0.1" && host != "localhost" && host != "::1"
}

func wellKnownURL(resourceURL string) string {
	u, err := url.Parse(resourceURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	u.Path = "/.well-known/oauth-protected-resource"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
