// Package passgen is human CLI password material. crypto/rand, not a cipher.
// Not an MCP tool. The value is not a vault secret until item add.
package passgen

import (
	"crypto/rand"
	"fmt"
)

const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

func New(n int) ([]byte, error) {
	if n < 12 || n > 128 {
		return nil, fmt.Errorf("passgen: length must be 12-128")
	}
	out := make([]byte, n)
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return out, nil
}
