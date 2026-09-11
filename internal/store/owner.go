package store

import (
	"database/sql"
	"fmt"

	"github.com/vortexnyc/password-manager/internal/crypto"
	"github.com/vortexnyc/password-manager/internal/protocol"
)

func ownerCacheKey(o protocol.Owner) string {
	return string(o.Kind) + "\x00" + o.ID
}

// ownerDEK is the per-owner data key. Master unwraps it. Grants never see it.
func (s *SQLite) ownerDEK(o protocol.Owner) ([]byte, error) {
	if o.Kind == "" || o.ID == "" {
		return nil, fmt.Errorf("store: missing owner")
	}
	k := ownerCacheKey(o)
	s.mu.Lock()
	if dek, ok := s.deks[k]; ok {
		s.mu.Unlock()
		return dek, nil
	}
	s.mu.Unlock()

	var wrapped []byte
	err := s.db.QueryRow(`SELECT wrapped FROM owner_keys WHERE owner_kind=? AND owner_id=?`, o.Kind, o.ID).Scan(&wrapped)
	if err == sql.ErrNoRows {
		return s.ensureOwner(o)
	}
	if err != nil {
		return nil, err
	}
	dek, err := crypto.Open(s.key, wrapped)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.deks[k] = dek
	s.mu.Unlock()
	return dek, nil
}

func (s *SQLite) ensureOwner(o protocol.Owner) ([]byte, error) {
	dek, err := crypto.NewKey()
	if err != nil {
		return nil, err
	}
	wrapped, err := crypto.Seal(s.key, dek)
	if err != nil {
		return nil, err
	}
	_, err = s.db.Exec(`INSERT INTO owner_keys(owner_kind, owner_id, wrapped) VALUES(?,?,?)
		ON CONFLICT(owner_kind, owner_id) DO NOTHING`, o.Kind, o.ID, wrapped)
	if err != nil {
		return nil, err
	}
	// Conflict: another writer created it. Unwrap theirs.
	var stored []byte
	if err := s.db.QueryRow(`SELECT wrapped FROM owner_keys WHERE owner_kind=? AND owner_id=?`, o.Kind, o.ID).Scan(&stored); err != nil {
		return nil, err
	}
	out, err := crypto.Open(s.key, stored)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.deks[ownerCacheKey(o)] = out
	s.mu.Unlock()
	return out, nil
}

// rewrapLegacy moves secrets sealed with master onto the owner DEK.
// Existing vaults stay readable. The grant still does not get a key.
func (s *SQLite) rewrapLegacy() error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM owner_keys`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	rows, err := s.db.Query(`SELECT id, owner_kind, owner_id, secret FROM items`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type row struct {
		id    string
		owner protocol.Owner
		blob  []byte
	}
	var items []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.owner.Kind, &r.owner.ID, &r.blob); err != nil {
			return err
		}
		items = append(items, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(items) == 0 {
		return nil
	}
	for _, r := range items {
		plain, err := crypto.Open(s.key, r.blob)
		if err != nil {
			return fmt.Errorf("store: legacy secret %s: %w", r.id, err)
		}
		dek, err := s.ownerDEK(r.owner)
		if err != nil {
			return err
		}
		blob, err := crypto.Seal(dek, plain)
		if err != nil {
			return err
		}
		if _, err := s.db.Exec(`UPDATE items SET secret=? WHERE id=?`, blob, r.id); err != nil {
			return err
		}
	}
	return nil
}
