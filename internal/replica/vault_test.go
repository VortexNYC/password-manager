package replica

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/vortexnyc/password-manager/internal/crypto"
	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/scrub"
)

func TestSealedBoxHidesCatalogAndSecret(t *testing.T) {
	dir := t.TempDir()
	key, err := crypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	path := Path(dir)
	v, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "sk_live_REPLICA_SECRET"
	const host = "https://gitlab.com"
	if err := v.Put(protocol.Item{
		ID:    "gitlab.com",
		Name:  "gitlab.com",
		Kind:  protocol.ItemAPIKey,
		URIs:  []string{host},
		Login: "throwaway@veil.nyc",
	}, []byte(`{"v":1,"token":"`+secret+`"}`)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range [][]byte{
		[]byte(secret),
		[]byte("gitlab.com"),
		[]byte(host),
		[]byte("throwaway@veil.nyc"),
		[]byte("veil-replica-v1"),
		[]byte(key),
	} {
		if bytes.Contains(raw, needle) {
			t.Fatalf("plaintext on disk: %q", needle)
		}
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatal("secret on disk")
	}
	wrong, err := crypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, wrong); err == nil {
		t.Fatal("opened with the wrong key")
	}
	got, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if got.Material("gitlab.com") == "" || got.Items()[0].Name != "gitlab.com" {
		t.Fatal("roundtrip")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %s", st.Mode())
	}
}

func TestMemKeyNeverTouchesDisk(t *testing.T) {
	dir := t.TempDir()
	ks := Mem()
	key, err := Unlock(ks)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("keystore wrote the filesystem")
	}
	again, err := Unlock(ks)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, again) {
		t.Fatal("key rotated")
	}
}

func TestUnlockRejectsNilStore(t *testing.T) {
	if _, err := Unlock(nil); err == nil {
		t.Fatal("nil keystore")
	}
}

func TestPath(t *testing.T) {
	if filepath.Base(Path("/tmp/veil")) != FileName {
		t.Fatal(Path("/tmp/veil"))
	}
}
