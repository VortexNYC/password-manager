// Package totpenroll is human CLI TOTP enrollment. Not MCP. Not a vault item
// until item add --totp-file.
package totpenroll

import (
	"bytes"
	"fmt"
	"image/png"
	"strings"

	"github.com/pquerna/otp/totp"
)

const qrSize = 256

type Result struct {
	Seed string
	PNG  []byte
}

func Generate(issuer, account string) (Result, error) {
	issuer = strings.TrimSpace(issuer)
	account = strings.TrimSpace(account)
	if issuer == "" {
		return Result{}, fmt.Errorf("totp: issuer required")
	}
	if account == "" {
		return Result{}, fmt.Errorf("totp: account required")
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
	})
	if err != nil {
		return Result{}, err
	}
	img, err := key.Image(qrSize, qrSize)
	if err != nil {
		return Result{}, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return Result{}, err
	}
	return Result{Seed: key.Secret(), PNG: buf.Bytes()}, nil
}
