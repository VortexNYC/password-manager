package proxy

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateAndReloadCA(t *testing.T) {
	dir := t.TempDir()
	cert, pemBytes, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf == nil || !cert.Leaf.IsCA {
		t.Fatal("not a CA")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("bad pem")
	}
	if _, err := os.Stat(filepath.Join(dir, caKeyFile)); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, caKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("ca.key mode %s", st.Mode())
	}

	cert2, _, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.Leaf.Equal(cert2.Leaf) {
		t.Fatal("CA regenerated")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("pool")
	}
}
