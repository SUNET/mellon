package crypto

import (
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateKeyPair(t *testing.T) {
	for _, alg := range []Algorithm{RS256, ES256, EdDSA} {
		kp, err := GenerateKeyPair(alg, "test-kid")
		if err != nil {
			t.Fatalf("GenerateKeyPair(%s): %v", alg, err)
		}
		if kp.KID != "test-kid" {
			t.Errorf("KID = %q, want test-kid", kp.KID)
		}
		if kp.Algorithm != alg {
			t.Errorf("Algorithm = %q, want %q", kp.Algorithm, alg)
		}
	}

	_, err := GenerateKeyPair("UNSUPPORTED", "kid")
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

func TestSignAndValidateIDToken(t *testing.T) {
	for _, alg := range []Algorithm{RS256, ES256, EdDSA} {
		kp, _ := GenerateKeyPair(alg, "kid-"+string(alg))

		claims := IDTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:  "http://localhost",
				Subject: "user1",
			},
			Name:  "Test User",
			Email: "test@example.com",
		}

		tokenStr, err := kp.SignIDToken(claims)
		if err != nil {
			t.Fatalf("SignIDToken(%s): %v", alg, err)
		}

		tok, err := kp.ValidateToken(tokenStr)
		if err != nil {
			t.Fatalf("ValidateToken(%s): %v", alg, err)
		}
		if !tok.Valid {
			t.Errorf("token not valid for %s", alg)
		}
	}
}

func TestSignAndValidateAccessToken(t *testing.T) {
	kp, _ := GenerateKeyPair(RS256, "test-kid")

	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  "http://localhost",
			Subject: "user1",
		},
		Scope:    "openid profile",
		ClientID: "client1",
	}

	tokenStr, err := kp.SignAccessToken(claims)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := kp.ValidateToken(tokenStr)
	if err != nil {
		t.Fatal(err)
	}
	if !tok.Valid {
		t.Error("token not valid")
	}
}

func TestIDTokenClaimsMarshalJSON_WithExtra(t *testing.T) {
	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  "http://localhost",
			Subject: "user1",
		},
		Name: "Test",
		Extra: map[string]any{
			"birthdate":  "1990-01-15",
			"department": "engineering",
		},
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	json.Unmarshal(data, &m)

	if m["birthdate"] != "1990-01-15" {
		t.Errorf("birthdate = %v", m["birthdate"])
	}
	if m["department"] != "engineering" {
		t.Errorf("department = %v", m["department"])
	}
	if m["name"] != "Test" {
		t.Errorf("name = %v", m["name"])
	}
}

func TestIDTokenClaimsMarshalJSON_NoExtra(t *testing.T) {
	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user1",
		},
		Name: "Test",
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	json.Unmarshal(data, &m)

	if m["name"] != "Test" {
		t.Errorf("name = %v", m["name"])
	}
}

func TestAccessTokenClaimsMarshalJSON_WithExtra(t *testing.T) {
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user1",
		},
		Scope: "openid",
		Extra: map[string]any{
			"custom_attr": "value",
		},
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	json.Unmarshal(data, &m)

	if m["custom_attr"] != "value" {
		t.Errorf("custom_attr = %v", m["custom_attr"])
	}
	if m["scope"] != "openid" {
		t.Errorf("scope = %v", m["scope"])
	}
}

func TestAccessTokenClaimsMarshalJSON_NoExtra(t *testing.T) {
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user1",
		},
		Scope: "openid",
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	json.Unmarshal(data, &m)

	if m["scope"] != "openid" {
		t.Errorf("scope = %v", m["scope"])
	}
}

func TestExtraDoesNotOverrideStandardClaims(t *testing.T) {
	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "real-sub",
		},
		Name: "Real Name",
		Extra: map[string]any{
			"sub":  "attacker",
			"name": "Fake",
		},
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	json.Unmarshal(data, &m)

	if m["sub"] != "real-sub" {
		t.Errorf("sub should not be overridden: got %v", m["sub"])
	}
	if m["name"] != "Real Name" {
		t.Errorf("name should not be overridden: got %v", m["name"])
	}
}

func TestSignedTokenContainsExtraClaims(t *testing.T) {
	kp, _ := GenerateKeyPair(RS256, "kid")

	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  "http://localhost",
			Subject: "user1",
		},
		Extra: map[string]any{
			"birthdate": "2000-06-15",
		},
	}

	tokenStr, err := kp.SignIDToken(claims)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := kp.ValidateToken(tokenStr)
	if err != nil {
		t.Fatal(err)
	}

	mapClaims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("expected MapClaims")
	}
	if mapClaims["birthdate"] != "2000-06-15" {
		t.Errorf("birthdate in signed token = %v", mapClaims["birthdate"])
	}
}
