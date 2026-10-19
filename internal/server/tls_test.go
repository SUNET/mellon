package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// writeKeyPair writes a PEM cert/key pair with the given CN into dir and
// returns their paths.
func writeKeyPair(t *testing.T, dir, cn string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "server.crt.pem")
	keyPath := filepath.Join(dir, "server.key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func leafCN(t *testing.T, der []byte) string {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c.Subject.CommonName
}

func TestLoadTLSCertificate_ExplicitValid(t *testing.T) {
	certPath, keyPath := writeKeyPair(t, t.TempDir(), "explicit.example")
	cert, src, err := LoadTLSCertificate(TLSOptions{CertFile: certPath, KeyFile: keyPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src != "file:"+certPath {
		t.Errorf("source = %q", src)
	}
	if cn := leafCN(t, cert.Certificate[0]); cn != "explicit.example" {
		t.Errorf("CN = %q", cn)
	}
}

func TestLoadTLSCertificate_ExplicitTakesPrecedenceOverDefaults(t *testing.T) {
	certPath, keyPath := writeKeyPair(t, t.TempDir(), "explicit.example")
	defCert, defKey := writeKeyPair(t, t.TempDir(), "default.example")
	cert, _, err := LoadTLSCertificate(TLSOptions{
		CertFile: certPath, KeyFile: keyPath,
		DefaultCertFile: defCert, DefaultKeyFile: defKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cn := leafCN(t, cert.Certificate[0]); cn != "explicit.example" {
		t.Errorf("CN = %q, want explicit.example", cn)
	}
}

func TestLoadTLSCertificate_ExplicitErrors(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeyPair(t, dir, "x")
	badPath := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		opts TLSOptions
	}{
		{"only cert", TLSOptions{CertFile: certPath}},
		{"only key", TLSOptions{KeyFile: keyPath}},
		{"missing cert file", TLSOptions{CertFile: filepath.Join(dir, "nope.pem"), KeyFile: keyPath}},
		{"missing key file", TLSOptions{CertFile: certPath, KeyFile: filepath.Join(dir, "nope.pem")}},
		{"invalid cert PEM", TLSOptions{CertFile: badPath, KeyFile: keyPath}},
		{"invalid key PEM", TLSOptions{CertFile: certPath, KeyFile: badPath}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Valid defaults must not mask an explicit misconfiguration.
			tt.opts.DefaultCertFile, tt.opts.DefaultKeyFile = certPath, keyPath
			if _, _, err := LoadTLSCertificate(tt.opts); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestLoadTLSCertificate_DefaultsValid(t *testing.T) {
	certPath, keyPath := writeKeyPair(t, t.TempDir(), "default.example")
	cert, src, err := LoadTLSCertificate(TLSOptions{DefaultCertFile: certPath, DefaultKeyFile: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	if src != "file:"+certPath {
		t.Errorf("source = %q", src)
	}
	if cn := leafCN(t, cert.Certificate[0]); cn != "default.example" {
		t.Errorf("CN = %q", cn)
	}
}

func TestLoadTLSCertificate_DefaultsFallBack(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeyPair(t, dir, "default.example")
	badPath := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badPath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.pem")

	tests := []struct {
		name     string
		cert     string
		key      string
		wantWarn bool
	}{
		{"neither exists", missing, missing + "2", false},
		{"only cert exists", certPath, missing, true},
		{"only key exists", missing, keyPath, true},
		{"invalid pair", badPath, keyPath, true},
		{"directory instead of file", dir, keyPath, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLog(t)
			cert, src, err := LoadTLSCertificate(TLSOptions{DefaultCertFile: tt.cert, DefaultKeyFile: tt.key})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if src != "self-signed" {
				t.Errorf("source = %q, want self-signed", src)
			}
			if cn := leafCN(t, cert.Certificate[0]); cn != "mellon" {
				t.Errorf("CN = %q, want mellon", cn)
			}
			if got := strings.Contains(logs.String(), "WARNING"); got != tt.wantWarn {
				t.Errorf("warning logged = %v, want %v (log: %q)", got, tt.wantWarn, logs.String())
			}
		})
	}
}

func TestLoadTLSCertificate_SelfSignedSANs(t *testing.T) {
	cert, src, err := LoadTLSCertificate(TLSOptions{Hosts: []string{"Mellon.Example", "10.1.2.3", "localhost", "[::1]"}})
	if err != nil {
		t.Fatal(err)
	}
	if src != "self-signed" {
		t.Errorf("source = %q", src)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	slices.Sort(leaf.DNSNames)
	if want := []string{"localhost", "mellon.example"}; !slices.Equal(leaf.DNSNames, want) {
		t.Errorf("DNSNames = %v, want %v", leaf.DNSNames, want)
	}
	var ips []string
	for _, ip := range leaf.IPAddresses {
		ips = append(ips, ip.String())
	}
	slices.Sort(ips)
	if want := []string{"10.1.2.3", "127.0.0.1", "::1"}; !slices.Equal(ips, want) {
		t.Errorf("IPAddresses = %v, want %v", ips, want)
	}
	if err := leaf.VerifyHostname("mellon.example"); err != nil {
		t.Errorf("VerifyHostname: %v", err)
	}
	if err := leaf.VerifyHostname("10.1.2.3"); err != nil {
		t.Errorf("VerifyHostname(IP): %v", err)
	}
	if cert.PrivateKey == nil {
		t.Error("private key missing")
	}
}

func TestGenerateSelfSignedCert_UniqueSerials(t *testing.T) {
	a, err := generateSelfSignedCert(nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := generateSelfSignedCert(nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Leaf.SerialNumber.Cmp(b.Leaf.SerialNumber) == 0 {
		t.Error("expected distinct serial numbers")
	}
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return &buf
}
