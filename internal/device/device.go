// Package device wraps master to a second machine.
// The library is golang.org/x/crypto/nacl/box — same as fill.
// Pairing does not pair a model. It does not sync a second vault.
package device

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"

	"github.com/vortexnyc/password-manager/internal/crypto"
)

const (
	PublicSize  = 32
	PrivateSize = 32
)

// Generate returns a curve25519 keypair. The private key stays in a file.
func Generate() (pub, priv []byte, err error) {
	p, s, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return p[:], s[:], nil
}

// Public derives the box public key from a 32-byte private key.
func Public(priv []byte) ([]byte, error) {
	sk, err := as32(priv)
	if err != nil {
		return nil, err
	}
	pub, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// Offer seals master to peerPub with SealAnonymous.
// The grant never sees this. JSON must not carry the blob.
func Offer(master, peerPub []byte) ([]byte, error) {
	if len(master) != crypto.KeySize {
		return nil, fmt.Errorf("device: master")
	}
	pk, err := as32(peerPub)
	if err != nil {
		return nil, err
	}
	return box.SealAnonymous(nil, master, pk, rand.Reader)
}

// Accept opens a blob from Offer with the recipient private key.
func Accept(blob, priv []byte) ([]byte, error) {
	sk, err := as32(priv)
	if err != nil {
		return nil, err
	}
	pub, err := Public(priv)
	if err != nil {
		return nil, err
	}
	pk, err := as32(pub)
	if err != nil {
		return nil, err
	}
	master, ok := box.OpenAnonymous(nil, blob, pk, sk)
	if !ok {
		return nil, crypto.ErrAuth
	}
	if len(master) != crypto.KeySize {
		return nil, crypto.ErrAuth
	}
	return master, nil
}

func as32(b []byte) (*[32]byte, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("device: key")
	}
	var k [32]byte
	copy(k[:], b)
	return &k, nil
}
