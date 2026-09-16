package app

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/vortexnyc/password-manager/internal/crypto"
)

func TestDecodeMasterEnvRejectsEmpty(t *testing.T) {
	_, err := decodeMasterEnv("")
	if err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestDecodeMasterEnvRejectsNonHex(t *testing.T) {
	_, err := decodeMasterEnv("not-hex")
	if err == nil {
		t.Fatal("expected error for non-hex key")
	}
}

func TestDecodeMasterEnvRejectsWrongLength(t *testing.T) {
	_, err := decodeMasterEnv(hex.EncodeToString([]byte("short")))
	if err == nil {
		t.Fatal("expected error for wrong-length key")
	}
}

func TestDecodeMasterEnvAcceptsExactLength(t *testing.T) {
	key, err := crypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeMasterEnv(hex.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(key) {
		t.Fatalf("decoded key does not match")
	}
}

func TestLoadMasterPrefersEnvOverFile(t *testing.T) {
	dir := t.TempDir()
	envKey, err := crypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEIL_MASTER_KEY", hex.EncodeToString(envKey))

	// Drop a legacy master.key in the dir; env should win.
	if err := os.WriteFile(filepath.Join(dir, keyFile), []byte("legacy-master-key-is-ignored"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := loadMaster(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(envKey) {
		t.Fatalf("loadMaster did not prefer VEIL_MASTER_KEY")
	}
}
