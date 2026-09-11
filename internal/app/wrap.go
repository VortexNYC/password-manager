package app

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vortexnyc/password-manager/internal/device"
)

const (
	deviceFile = "device.key"
	wrapsDir   = "wraps"
	keyFile    = "master.key"
)

func wrapFile(dir string, pub []byte) string {
	return filepath.Join(dir, wrapsDir, hex.EncodeToString(pub))
}

func persistWrap(dir string, pub, blob []byte) error {
	if err := os.MkdirAll(filepath.Join(dir, wrapsDir), 0o700); err != nil {
		return err
	}
	return os.WriteFile(wrapFile(dir, pub), blob, 0o600)
}

func wrapMaster(dir string, master, priv []byte) error {
	pub, err := device.Public(priv)
	if err != nil {
		return err
	}
	blob, err := device.Offer(master, pub)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, deviceFile), priv, 0o600); err != nil {
		return err
	}
	return persistWrap(dir, pub, blob)
}

func hasWraps(dir string) bool {
	entries, err := os.ReadDir(filepath.Join(dir, wrapsDir))
	return err == nil && len(entries) > 0
}

func loadMaster(dir string) ([]byte, error) {
	if hasWraps(dir) {
		return unwrapLocal(dir)
	}
	master, err := os.ReadFile(filepath.Join(dir, keyFile))
	if err != nil {
		return nil, err
	}
	if err := migrateWraps(dir, master); err != nil {
		return nil, err
	}
	return master, nil
}

func unwrapLocal(dir string) ([]byte, error) {
	priv, err := os.ReadFile(filepath.Join(dir, deviceFile))
	if err != nil {
		return nil, err
	}
	pub, err := device.Public(priv)
	if err != nil {
		return nil, err
	}
	blob, err := os.ReadFile(wrapFile(dir, pub))
	if err != nil {
		return nil, err
	}
	return device.Accept(blob, priv)
}

func migrateWraps(dir string, master []byte) error {
	priv, err := os.ReadFile(filepath.Join(dir, deviceFile))
	if errors.Is(err, os.ErrNotExist) {
		_, priv, err = device.Generate()
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := wrapMaster(dir, master, priv); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, keyFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("app: migrate master: %w", err)
	}
	return nil
}
