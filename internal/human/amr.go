package human

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// AMR reads the Hydra id_token amr claim. ok is false when the token is not a JWT.
func AMR(raw string) ([]string, bool) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 || parts[1] == "" {
		return nil, false
	}
	p := parts[1]
	if n := len(p) % 4; n != 0 {
		p += strings.Repeat("=", 4-n)
	}
	payload, err := base64.URLEncoding.DecodeString(p)
	if err != nil {
		return nil, false
	}
	var claims struct {
		Amr []string `json:"amr"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return nil, false
	}
	return claims.Amr, true
}

// RequireTOTP rejects an id token whose amr skipped TOTP. Opaque test tokens
// are not JWTs and are left alone.
func RequireTOTP(raw string) error {
	amr, ok := AMR(raw)
	if !ok {
		return nil
	}
	for _, m := range amr {
		if m == "totp" {
			return nil
		}
	}
	return fmt.Errorf("human: id token amr must include totp")
}
