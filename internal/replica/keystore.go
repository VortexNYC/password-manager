package replica

import (
	"errors"
	"sync"

	"github.com/vortexnyc/password-manager/internal/crypto"
)

var ErrNotFound = errors.New("replica: key not found")

// KeyStore holds the 256-bit replica key off the filesystem.
// Mac: Keychain, this-device, fill host only. Not device.key.
type KeyStore interface {
	Get() ([]byte, error)
	Put([]byte) error
}

type mem struct {
	mu  sync.Mutex
	key []byte
}

func Mem() KeyStore { return &mem{} }

func (m *mem) Get() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.key) == 0 {
		return nil, ErrNotFound
	}
	if len(m.key) != crypto.KeySize {
		return nil, errors.New("replica: invalid stored key")
	}
	return append([]byte(nil), m.key...), nil
}

func (m *mem) Put(key []byte) error {
	if len(key) != crypto.KeySize {
		return errors.New("replica: key")
	}
	m.mu.Lock()
	m.key = append([]byte(nil), key...)
	m.mu.Unlock()
	return nil
}

func Unlock(ks KeyStore) ([]byte, error) {
	if ks == nil {
		return nil, errors.New("replica: no keystore")
	}
	key, err := ks.Get()
	if err == nil {
		if len(key) != crypto.KeySize {
			return nil, errors.New("replica: invalid stored key")
		}
		return key, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	key, err = crypto.NewKey()
	if err != nil {
		return nil, err
	}
	if err := ks.Put(key); err != nil {
		return nil, err
	}
	return key, nil
}
