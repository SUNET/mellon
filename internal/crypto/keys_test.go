package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestLoadRSAPrivateKeyFromPEM_PKCS1(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	kp, err := LoadRSAPrivateKeyFromPEM(string(pemData), "test-kid")
	if err != nil {
		t.Fatal(err)
	}
	if kp.Algorithm != RS256 {
		t.Errorf("Algorithm = %q, want RS256", kp.Algorithm)
	}
	if kp.KID != "test-kid" {
		t.Errorf("KID = %q", kp.KID)
	}
}

func TestLoadRSAPrivateKeyFromPEM_PKCS8(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs8Bytes, _ := x509.MarshalPKCS8PrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	kp, err := LoadRSAPrivateKeyFromPEM(string(pemData), "kid8")
	if err != nil {
		t.Fatal(err)
	}
	if kp.Algorithm != RS256 {
		t.Errorf("Algorithm = %q, want RS256", kp.Algorithm)
	}
}

func TestLoadRSAPrivateKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := LoadRSAPrivateKeyFromPEM("not pem data", "kid")
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestLoadRSAPrivateKeyFromPEM_UnsupportedBlockType(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("fake"),
	})
	_, err := LoadRSAPrivateKeyFromPEM(string(pemData), "kid")
	if err == nil {
		t.Error("expected error for unsupported block type")
	}
}

func TestJWK_RSA(t *testing.T) {
	kp, _ := GenerateKeyPair(RS256, "rsa-kid")
	jwk := kp.JWK()
	if jwk.KTY != "RSA" {
		t.Errorf("KTY = %q", jwk.KTY)
	}
	if jwk.ALG != "RS256" {
		t.Errorf("ALG = %q", jwk.ALG)
	}
	if jwk.N == "" || jwk.E == "" {
		t.Error("N and E should be set")
	}
}

func TestJWK_EC(t *testing.T) {
	kp, _ := GenerateKeyPair(ES256, "ec-kid")
	jwk := kp.JWK()
	if jwk.KTY != "EC" {
		t.Errorf("KTY = %q", jwk.KTY)
	}
	if jwk.CRV != "P-256" {
		t.Errorf("CRV = %q", jwk.CRV)
	}
	if jwk.X == "" || jwk.Y == "" {
		t.Error("X and Y should be set")
	}
}

func TestJWK_EdDSA(t *testing.T) {
	kp, _ := GenerateKeyPair(EdDSA, "ed-kid")
	jwk := kp.JWK()
	if jwk.KTY != "OKP" {
		t.Errorf("KTY = %q", jwk.KTY)
	}
	if jwk.CRV != "Ed25519" {
		t.Errorf("CRV = %q", jwk.CRV)
	}
	if jwk.X == "" {
		t.Error("X should be set")
	}
}
