package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	caCertFile = "ca.pem"
	caKeyFile  = "ca.key"
)

// GenerateCA makes a local-only ECDSA P-256 CA. Used for goproxy MITM.
// Source: crypto/x509; MITM CONNECT handling stays in elazarl/goproxy.
func GenerateCA() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"VortexNYC"},
			CommonName:   "password-manager local CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	return certPEM, keyPEM, nil
}

func LoadOrCreateCA(dir string) (tls.Certificate, []byte, error) {
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return tls.Certificate{}, nil, err
		}
		certPEM, keyPEM, err := GenerateCA()
		if err != nil {
			return tls.Certificate{}, nil, err
		}
		if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
			return tls.Certificate{}, nil, err
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			return tls.Certificate{}, nil, err
		}
		return parseCA(certPEM, keyPEM)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("proxy: ca.pem present but ca.key missing: %w", err)
	}
	return parseCA(certPEM, keyPEM)
}

func parseCA(certPEM, keyPEM []byte) (tls.Certificate, []byte, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	if len(cert.Certificate) > 0 {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return tls.Certificate{}, nil, err
		}
	}
	return cert, certPEM, nil
}

func CACertPath(dir string) string { return filepath.Join(dir, caCertFile) }
