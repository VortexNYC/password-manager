// Package replica is the fill host's local cache. One sealed box.
// Names, URIs, logins, and material all live inside the AEAD.
// The wrapping key is never a file next to the box. Agents who copy
// replica.box get ciphertext they cannot grind (random 256-bit key,
// not a password). 1Password/Bitwarden encrypt the whole local vault
// the same way; they do not leave a device.key beside plaintext sqlite
// metadata.
package replica

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vortexnyc/password-manager/internal/crypto"
	"github.com/vortexnyc/password-manager/internal/protocol"
)

const (
	FileName = "replica.box"
	Version  = 1
	magic    = "veil-replica-v1\n"
)

type Row struct {
	Item     protocol.Item `json:"item"`
	Material string        `json:"material"`
}

type disk struct {
	V     int   `json:"v"`
	Items []Row `json:"items"`
}

type Vault struct {
	path string
	key  []byte
	rows []Row
}

func Path(dir string) string {
	return filepath.Join(dir, FileName)
}

func Open(path string, key []byte) (*Vault, error) {
	if len(key) != crypto.KeySize {
		return nil, fmt.Errorf("replica: key")
	}
	v := &Vault{path: path, key: append([]byte(nil), key...)}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return v, nil
		}
		return nil, err
	}
	plain, err := crypto.Open(key, raw)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(plain, []byte(magic)) {
		return nil, crypto.ErrAuth
	}
	var d disk
	if json.Unmarshal(plain[len(magic):], &d) != nil || d.V != Version {
		return nil, fmt.Errorf("replica: box")
	}
	v.rows = d.Items
	if v.rows == nil {
		v.rows = []Row{}
	}
	return v, nil
}

func (v *Vault) Close() {
	if v == nil {
		return
	}
	for i := range v.key {
		v.key[i] = 0
	}
	v.rows = nil
}

func (v *Vault) Len() int {
	if v == nil {
		return 0
	}
	return len(v.rows)
}

func (v *Vault) Items() []protocol.Item {
	if v == nil {
		return nil
	}
	out := make([]protocol.Item, 0, len(v.rows))
	for _, r := range v.rows {
		out = append(out, r.Item)
	}
	return out
}

func (v *Vault) Material(id string) string {
	if v == nil {
		return ""
	}
	for _, r := range v.rows {
		if r.Item.ID == id {
			return r.Material
		}
	}
	return ""
}

func (v *Vault) Put(item protocol.Item, material []byte) error {
	if v == nil || item.ID == "" || len(material) == 0 {
		return fmt.Errorf("replica: put")
	}
	row := Row{Item: item, Material: string(material)}
	for i, r := range v.rows {
		if r.Item.ID == item.ID {
			v.rows[i] = row
			return v.flush()
		}
	}
	v.rows = append(v.rows, row)
	return v.flush()
}

func (v *Vault) flush() error {
	if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
		return err
	}
	body, err := json.Marshal(disk{V: Version, Items: v.rows})
	if err != nil {
		return err
	}
	plain := append([]byte(magic), body...)
	box, err := crypto.Seal(v.key, plain)
	if err != nil {
		return err
	}
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, box, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, v.path)
}
