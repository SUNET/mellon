package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
)

type Algorithm string

const (
	RS256 Algorithm = "RS256"
	ES256 Algorithm = "ES256"
	EdDSA Algorithm = "EdDSA"
)

type KeyPair struct {
	Algorithm  Algorithm
	KID        string
	PrivateKey crypto.Signer
	PublicKey  crypto.PublicKey
}

func GenerateKeyPair(alg Algorithm, kid string) (*KeyPair, error) {
	switch alg {
	case RS256:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate RSA key: %w", err)
		}
		return &KeyPair{Algorithm: alg, KID: kid, PrivateKey: key, PublicKey: &key.PublicKey}, nil
	case ES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ECDSA key: %w", err)
		}
		return &KeyPair{Algorithm: alg, KID: kid, PrivateKey: key, PublicKey: &key.PublicKey}, nil
	case EdDSA:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate Ed25519 key: %w", err)
		}
		return &KeyPair{Algorithm: alg, KID: kid, PrivateKey: priv, PublicKey: pub}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

// LoadRSAPrivateKeyFromPEM parses a PEM-encoded RSA private key (PKCS1 or PKCS8).
func LoadRSAPrivateKeyFromPEM(pemData string, kid string) (*KeyPair, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS1 private key: %w", err)
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8 private key: %w", err)
		}
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not RSA")
		}
		key = rsaKey
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
	return &KeyPair{Algorithm: RS256, KID: kid, PrivateKey: key, PublicKey: &key.PublicKey}, nil
}

type JWK struct {
	KTY string `json:"kty"`
	Use string `json:"use"`
	KID string `json:"kid"`
	ALG string `json:"alg"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	CRV string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

func (kp *KeyPair) JWK() JWK {
	switch pub := kp.PublicKey.(type) {
	case *rsa.PublicKey:
		return JWK{
			KTY: "RSA",
			Use: "sig",
			KID: kp.KID,
			ALG: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}
	case *ecdsa.PublicKey:
		return JWK{
			KTY: "EC",
			Use: "sig",
			KID: kp.KID,
			ALG: "ES256",
			CRV: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
			Y:   base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
		}
	case ed25519.PublicKey:
		return JWK{
			KTY: "OKP",
			Use: "sig",
			KID: kp.KID,
			ALG: "EdDSA",
			CRV: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pub),
		}
	default:
		return JWK{}
	}
}
