// Package crypto wraps golang.org/x/crypto. Do not invent AEAD or KDFs.
package crypto

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

var ErrAuth = errors.New("crypto: authentication failed")

const KeySize = chacha20poly1305.KeySize

func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// Seal returns nonce||ciphertext. key must be KeySize bytes.
// This is also the owner-key wrap: master seals the per-owner DEK.
func Seal(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func Open(key, blob []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize() {
		return nil, ErrAuth
	}
	nonce, ct := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrAuth
	}
	return plain, nil
}
