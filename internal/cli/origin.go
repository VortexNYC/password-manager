package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vortexnyc/password-manager/identity/glue"
	"github.com/vortexnyc/password-manager/internal/id"
	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/publicapi"
)

const jwtRefreshSkew = 2 * time.Minute

func originBase() string {
	return strings.TrimRight(strings.TrimSpace(os.Getenv("PWM_ORIGIN")), "/")
}

func originToken(tokenFile string) (string, error) {
	if tokenFile != "" {
		b, err := readFileMaterial(tokenFile)
		if err != nil {
			return "", err
		}
		if len(b) == 0 {
			return "", fmt.Errorf("origin: empty token file")
		}
		return string(b), nil
	}
	if f := strings.TrimSpace(os.Getenv("PWM_OIDC_TOKEN_FILE")); f != "" {
		b, err := readFileMaterial(f)
		if err != nil {
			return "", err
		}
		if len(b) == 0 {
			return "", fmt.Errorf("origin: empty PWM_OIDC_TOKEN_FILE")
		}
		return string(b), nil
	}
	if t := strings.TrimSpace(os.Getenv("PWM_OIDC_TOKEN")); t != "" {
		return t, nil
	}
	return "", fmt.Errorf("origin: --oidc-token-file, PWM_OIDC_TOKEN_FILE, or PWM_OIDC_TOKEN is required")
}

func originTokenLive(ctx context.Context, tokenFile string) (string, error) {
	tok, err := originToken(tokenFile)
	if err == nil && !jwtNeedsRefresh(tok) {
		return tok, nil
	}
	secretFile := strings.TrimSpace(os.Getenv("PWM_HYDRA_SECRET_FILE"))
	if secretFile == "" {
		if err != nil {
			return "", err
		}
		return tok, nil
	}
	minted, err := originRemint(ctx, tokenFile, secretFile)
	if err != nil {
		return "", err
	}
	return minted, nil
}

func jwtNeedsRefresh(tok string) bool {
	exp, ok := jwtExpUnix(tok)
	if !ok {
		return false
	}
	return time.Now().Add(jwtRefreshSkew).Unix() >= exp
}

func jwtExpUnix(tok string) (int64, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[1] == "" {
		return 0, false
	}
	p := parts[1]
	if n := len(p) % 4; n != 0 {
		p += strings.Repeat("=", 4-n)
	}
	raw, err := base64.URLEncoding.DecodeString(p)
	if err != nil {
		return 0, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(raw, &claims) != nil || claims.Exp == 0 {
		return 0, false
	}
	return claims.Exp, true
}

func originRemint(ctx context.Context, tokenFile, secretFile string) (string, error) {
	secret, err := readFileMaterial(secretFile)
	if err != nil {
		return "", err
	}
	if len(secret) == 0 {
		return "", fmt.Errorf("origin: empty PWM_HYDRA_SECRET_FILE")
	}
	issuer := strings.TrimSpace(os.Getenv("PWM_HYDRA_ISSUER"))
	if issuer == "" {
		return "", fmt.Errorf("origin: PWM_HYDRA_ISSUER is required to remint")
	}
	agentName := strings.TrimSpace(os.Getenv("PWM_AGENT"))
	if agentName == "" {
		if tok, err := originToken(tokenFile); err == nil {
			agentName = agentNameFromJWT(tok)
		}
	}
	if !id.Valid(agentName) {
		return "", fmt.Errorf("origin: PWM_AGENT is required to remint")
	}
	audience := envOr("PWM_HYDRA_CLIENT_ID", glue.DefaultClientID)
	raw, err := glue.ClientCredentials(ctx, issuer, glue.AgentClientID(agentName), string(secret), audience)
	if err != nil {
		return "", err
	}
	out := tokenFile
	if out == "" {
		out = strings.TrimSpace(os.Getenv("PWM_OIDC_TOKEN_FILE"))
	}
	if out != "" {
		if err := os.WriteFile(out, []byte(raw+"\n"), 0o600); err != nil {
			return "", err
		}
	}
	return raw, nil
}

func agentNameFromJWT(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return ""
	}
	p := parts[1]
	if n := len(p) % 4; n != 0 {
		p += strings.Repeat("=", 4-n)
	}
	raw, err := base64.URLEncoding.DecodeString(p)
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return ""
	}
	sub := strings.TrimSpace(claims.Sub)
	if strings.HasPrefix(sub, glue.AgentClientPrefix) {
		return strings.TrimPrefix(sub, glue.AgentClientPrefix)
	}
	return ""
}

func originDo(ctx context.Context, method, path, token string, body []byte) ([]byte, error) {
	base := originBase()
	if base == "" {
		return nil, fmt.Errorf("origin: PWM_ORIGIN is empty")
	}
	var rdr io.Reader
	if len(body) > 0 {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return raw, fmt.Errorf("origin %s %s: http %d", method, path, res.StatusCode)
	}
	return raw, nil
}

func originUse(cmd *cobra.Command, tokenFile, item, rawURL, method string, headers []string, bodyFile string) error {
	tok, err := originTokenLive(cmd.Context(), tokenFile)
	if err != nil {
		return err
	}
	in := publicapi.UseRequest{Item: item, URL: rawURL, Method: method, Headers: map[string]string{}}
	for _, h := range headers {
		k, v, ok := strings.Cut(h, ":")
		if !ok || strings.TrimSpace(k) == "" {
			return fmt.Errorf("use: --header is Name: value")
		}
		in.Headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if bodyFile != "" {
		b, err := os.ReadFile(bodyFile)
		if err != nil {
			return err
		}
		in.Body = string(b)
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	raw, err := originDo(cmd.Context(), http.MethodPost, "/v1/use", tok, payload)
	if err != nil {
		return err
	}
	var out useDTO
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	return encode(cmd, out)
}

func originEvents(cmd *cobra.Command, tokenFile string) error {
	tok, err := originTokenLive(cmd.Context(), tokenFile)
	if err != nil {
		return err
	}
	raw, err := originDo(cmd.Context(), http.MethodGet, "/v1/events", tok, nil)
	if err != nil {
		return err
	}
	var out publicapi.EventsResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	if out.Events == nil {
		out.Events = []protocol.AuditEvent{}
	}
	return encode(cmd, out.Events)
}

func originItemList(cmd *cobra.Command) error {
	tok, err := originOwnerToken(cmd.Context())
	if err != nil {
		return err
	}
	raw, err := originDo(cmd.Context(), http.MethodGet, "/v1/items", tok, nil)
	if err != nil {
		return err
	}
	var out publicapi.ItemsResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	if out.Items == nil {
		out.Items = []protocol.Item{}
	}
	return encode(cmd, out.Items)
}

func originItemAdd(cmd *cobra.Command, name, uri string, tags []string, kind protocol.ItemKind, token, totpSeed []byte, login string) error {
	tok, err := originHumanToken()
	if err != nil {
		return err
	}
	in := publicapi.CreateItemRequest{
		Name:     name,
		URI:      uri,
		Tags:     tags,
		Kind:     string(kind),
		Secret:   string(token),
		TOTPSeed: string(totpSeed),
		Login:    login,
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	raw, err := originDo(cmd.Context(), http.MethodPost, "/v1/items", tok, payload)
	if err != nil {
		return err
	}
	var item protocol.Item
	if err := json.Unmarshal(raw, &item); err != nil {
		return err
	}
	return encode(cmd, item)
}

func originItemUpdate(cmd *cobra.Command, name string, addURIs, tags []string, login string) error {
	tok, err := originHumanToken()
	if err != nil {
		return err
	}
	patches := addURIs
	if len(patches) == 0 {
		patches = []string{""}
	}
	var last []byte
	for i, u := range patches {
		in := publicapi.UpdateItemRequest{URI: u}
		if i == 0 {
			in.Tags = tags
			in.Login = login
		}
		payload, err := json.Marshal(in)
		if err != nil {
			return err
		}
		last, err = originDo(cmd.Context(), http.MethodPatch, "/v1/items/"+name, tok, payload)
		if err != nil {
			return err
		}
	}
	var item protocol.Item
	if err := json.Unmarshal(last, &item); err != nil {
		return err
	}
	return encode(cmd, item)
}

func originItemArchive(cmd *cobra.Command, name string) error {
	tok, err := originHumanToken()
	if err != nil {
		return err
	}
	raw, err := originDo(cmd.Context(), http.MethodPost, "/v1/items/"+name+"/archive", tok, nil)
	if err != nil {
		return err
	}
	var out map[string]bool
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	return encode(cmd, out)
}

func originItemDelete(cmd *cobra.Command, name string) error {
	tok, err := originHumanToken()
	if err != nil {
		return err
	}
	raw, err := originDo(cmd.Context(), http.MethodDelete, "/v1/items/"+name, tok, nil)
	if err != nil {
		return err
	}
	var out map[string]bool
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	return encode(cmd, out)
}

func originGrantAdd(cmd *cobra.Command, grantee, item, level string, expires time.Duration, asHuman bool) error {
	tok, err := originHumanToken()
	if err != nil {
		return err
	}
	in := publicapi.CreateGrantRequest{Item: item, Level: level}
	if asHuman {
		in.Human = grantee
	} else {
		in.Agent = grantee
	}
	if expires > 0 {
		in.Expires = expires.String()
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	raw, err := originDo(cmd.Context(), http.MethodPost, "/v1/grants", tok, payload)
	if err != nil {
		return err
	}
	var out publicapi.GrantView
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	return encode(cmd, out)
}

func originGrantList(cmd *cobra.Command) error {
	tok, err := originHumanToken()
	if err != nil {
		return err
	}
	raw, err := originDo(cmd.Context(), http.MethodGet, "/v1/grants", tok, nil)
	if err != nil {
		return err
	}
	var out publicapi.GrantsResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	if out.Grants == nil {
		out.Grants = []publicapi.GrantView{}
	}
	return encode(cmd, out.Grants)
}
