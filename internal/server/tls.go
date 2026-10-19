package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// Default locations probed for a TLS certificate/key pair when none is
// configured explicitly. These follow the Keycloak container convention.
const (
	DefaultCertPath = "/opt/keycloak/conf/server.crt.pem"
	DefaultKeyPath  = "/opt/keycloak/conf/server.key.pem"
)

// TLSOptions controls where the HTTPS certificate is loaded from.
type TLSOptions struct {
	// CertFile and KeyFile are explicitly configured paths. If either is
	// set, both must be set and must load successfully.
	CertFile string
	KeyFile  string

	// DefaultCertFile and DefaultKeyFile are probed when no explicit paths
	// are configured. Problems here are logged and fall back to self-signed.
	DefaultCertFile string
	DefaultKeyFile  string

	// Hosts are extra DNS names or IP addresses added to a self-signed
	// certificate's SANs.
	Hosts []string
}

// LoadTLSCertificate resolves the HTTPS certificate in this order:
// explicit files (fail hard), default mount paths (warn and fall back),
// then a freshly generated self-signed certificate. The returned source
// describes where the certificate came from.
func LoadTLSCertificate(opts TLSOptions) (tls.Certificate, string, error) {
	if opts.CertFile != "" || opts.KeyFile != "" {
		if opts.CertFile == "" || opts.KeyFile == "" {
			return tls.Certificate{}, "", errors.New("both TLS certificate file and key file must be set")
		}
		cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
		if err != nil {
			return tls.Certificate{}, "", fmt.Errorf("load TLS key pair (cert %s, key %s): %w", opts.CertFile, opts.KeyFile, err)
		}
		warnIfExpired(cert, opts.CertFile)
		return cert, "file:" + opts.CertFile, nil
	}

	if opts.DefaultCertFile != "" && opts.DefaultKeyFile != "" {
		certExists := fileExists(opts.DefaultCertFile)
		keyExists := fileExists(opts.DefaultKeyFile)
		switch {
		case certExists && keyExists:
			cert, err := tls.LoadX509KeyPair(opts.DefaultCertFile, opts.DefaultKeyFile)
			if err == nil {
				warnIfExpired(cert, opts.DefaultCertFile)
				return cert, "file:" + opts.DefaultCertFile, nil
			}
			log.Printf("WARNING: failed to load TLS key pair from %s / %s: %v; falling back to self-signed certificate",
				opts.DefaultCertFile, opts.DefaultKeyFile, err)
		case certExists:
			log.Printf("WARNING: found %s but not %s; falling back to self-signed certificate",
				opts.DefaultCertFile, opts.DefaultKeyFile)
		case keyExists:
			log.Printf("WARNING: found %s but not %s; falling back to self-signed certificate",
				opts.DefaultKeyFile, opts.DefaultCertFile)
		}
	}

	cert, err := generateSelfSignedCert(opts.Hosts)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate self-signed TLS certificate: %w", err)
	}
	return cert, "self-signed", nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Printf("WARNING: cannot stat %s: %v", path, err)
		}
		return false
	}
	return !info.IsDir()
}

func warnIfExpired(cert tls.Certificate, path string) {
	leaf := cert.Leaf
	if leaf == nil && len(cert.Certificate) > 0 {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return
		}
		leaf = parsed
	}
	if leaf == nil {
		return
	}
	now := time.Now()
	if now.After(leaf.NotAfter) {
		log.Printf("WARNING: TLS certificate %s expired at %s", path, leaf.NotAfter.Format(time.RFC3339))
	} else if now.Before(leaf.NotBefore) {
		log.Printf("WARNING: TLS certificate %s is not valid until %s", path, leaf.NotBefore.Format(time.RFC3339))
	}
}

func generateSelfSignedCert(hosts []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	dnsNames, ips := splitHosts(append([]string{"localhost", "127.0.0.1", "::1"}, hosts...))

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "mellon"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// splitHosts separates hosts into deduplicated DNS names and IP addresses.
func splitHosts(hosts []string) ([]string, []net.IP) {
	var dnsNames []string
	var ips []net.IP
	seen := make(map[string]bool)
	for _, h := range hosts {
		h = strings.TrimSpace(strings.Trim(strings.TrimSpace(h), "[]"))
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			k := "ip:" + ip.String()
			if !seen[k] {
				seen[k] = true
				ips = append(ips, ip)
			}
			continue
		}
		h = strings.ToLower(h)
		k := "dns:" + h
		if !seen[k] {
			seen[k] = true
			dnsNames = append(dnsNames, h)
		}
	}
	return dnsNames, ips
}
