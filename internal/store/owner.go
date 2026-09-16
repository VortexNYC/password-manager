package store

import (
	"context"
	"fmt"
	"sync"

	"github.com/vortexnyc/password-manager/internal/crypto"
	"github.com/vortexnyc/password-manager/internal/protocol"
)

func ownerCacheKey(o protocol.Owner) string {
	return string(o.Kind) + "\x00" + o.ID
}

// ownerSource is the persistence surface a keyManager uses to load and store
// wrapped per-owner DEKs. SQLite and Postgres implement it.
type ownerSource interface {
	loadOwnerWrapped(ctx context.Context, o protocol.Owner) ([]byte, error)
	storeOwnerWrapped(ctx context.Context, o protocol.Owner, wrapped []byte) error
}

// keyManager holds the master key and an in-memory DEK cache.
// It does not depend on a particular database driver.
type keyManager struct {
	key  []byte
	mu   sync.Mutex
	deks map[string][]byte
}

func newKeyManager(key []byte) *keyManager {
	return &keyManager{
		key:  append([]byte(nil), key...),
		deks: map[string][]byte{},
	}
}

// ownerDEK is the per-owner data key. Master unwraps it. Grants never see it.
func (km *keyManager) ownerDEK(ctx context.Context, s ownerSource, o protocol.Owner) ([]byte, error) {
	if o.Kind == "" || o.ID == "" {
		return nil, fmt.Errorf("store: missing owner")
	}
	k := ownerCacheKey(o)
	km.mu.Lock()
	if dek, ok := km.deks[k]; ok {
		km.mu.Unlock()
		return dek, nil
	}
	km.mu.Unlock()

	wrapped, err := s.loadOwnerWrapped(ctx, o)
	if err == ErrNotFound {
		dek, err := crypto.NewKey()
		if err != nil {
			return nil, err
		}
		sealed, err := crypto.Seal(km.key, dek)
		if err != nil {
			return nil, err
		}
		if err := s.storeOwnerWrapped(ctx, o, sealed); err != nil {
			return nil, err
		}
		wrapped, err = s.loadOwnerWrapped(ctx, o)
		if err != nil {
			return nil, err
		}
		plain, err := crypto.Open(km.key, wrapped)
		if err != nil {
			return nil, err
		}
		km.mu.Lock()
		km.deks[k] = plain
		km.mu.Unlock()
		return plain, nil
	}
	if err != nil {
		return nil, err
	}
	plain, err := crypto.Open(km.key, wrapped)
	if err != nil {
		return nil, err
	}
	km.mu.Lock()
	km.deks[k] = plain
	km.mu.Unlock()
	return plain, nil
}
