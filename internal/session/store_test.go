package session

import (
	"testing"
	"time"
)

func TestCreateAndExchangeCode(t *testing.T) {
	s := NewStore()
	code := s.CreateCode("client1", "http://localhost/cb", "openid", "nonce", "user1", "", "", 60*time.Second)

	if code == "" {
		t.Fatal("expected non-empty code")
	}

	ac := s.ExchangeCode(code, "")
	if ac == nil {
		t.Fatal("expected auth code")
	}
	if ac.ClientID != "client1" {
		t.Errorf("ClientID = %q", ac.ClientID)
	}
	if ac.Username != "user1" {
		t.Errorf("Username = %q", ac.Username)
	}

	// Code should be consumed
	if s.ExchangeCode(code, "") != nil {
		t.Error("code should be single-use")
	}
}

func TestExchangeCode_Expired(t *testing.T) {
	s := NewStore()
	code := s.CreateCode("client1", "http://localhost/cb", "openid", "", "user1", "", "", 1*time.Nanosecond)
	time.Sleep(2 * time.Millisecond)

	if s.ExchangeCode(code, "") != nil {
		t.Error("expired code should return nil")
	}
}

func TestExchangeCode_PKCE(t *testing.T) {
	s := NewStore()
	// S256 challenge for verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// challenge = base64url(sha256(verifier))
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// Compute challenge manually
	code := s.CreateCode("client1", "http://localhost/cb", "openid", "", "user1", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256", 60*time.Second)

	ac := s.ExchangeCode(code, verifier)
	if ac == nil {
		t.Fatal("expected valid PKCE exchange")
	}
}

func TestExchangeCode_PKCE_Invalid(t *testing.T) {
	s := NewStore()
	code := s.CreateCode("client1", "http://localhost/cb", "openid", "", "user1", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256", 60*time.Second)

	if s.ExchangeCode(code, "wrong-verifier") != nil {
		t.Error("invalid PKCE verifier should fail")
	}
}

func TestRefreshToken(t *testing.T) {
	s := NewStore()
	rt := s.CreateRefreshToken("client1", "user1", "openid", 30*time.Minute)

	if rt == "" {
		t.Fatal("expected non-empty refresh token")
	}

	validated := s.ValidateRefreshToken(rt)
	if validated == nil {
		t.Fatal("expected valid refresh token")
	}
	if validated.ClientID != "client1" {
		t.Errorf("ClientID = %q", validated.ClientID)
	}

	s.RevokeRefreshToken(rt)
	if s.ValidateRefreshToken(rt) != nil {
		t.Error("revoked token should be invalid")
	}
}

func TestRefreshToken_Expired(t *testing.T) {
	s := NewStore()
	rt := s.CreateRefreshToken("client1", "user1", "openid", 1*time.Nanosecond)
	time.Sleep(2 * time.Millisecond)

	if s.ValidateRefreshToken(rt) != nil {
		t.Error("expired refresh token should return nil")
	}
}

func TestRefreshToken_NotFound(t *testing.T) {
	s := NewStore()
	if s.ValidateRefreshToken("nonexistent") != nil {
		t.Error("expected nil for unknown token")
	}
}

func TestAccessToken(t *testing.T) {
	s := NewStore()
	s.StoreAccessToken("at-123", "client1", "user1", "openid profile", 5*time.Minute)

	at := s.ValidateAccessToken("at-123")
	if at == nil {
		t.Fatal("expected valid access token")
	}
	if at.ClientID != "client1" {
		t.Errorf("ClientID = %q", at.ClientID)
	}
	if at.Username != "user1" {
		t.Errorf("Username = %q", at.Username)
	}
	if at.Scope != "openid profile" {
		t.Errorf("Scope = %q", at.Scope)
	}
}

func TestAccessToken_Expired(t *testing.T) {
	s := NewStore()
	s.StoreAccessToken("at-expired", "client1", "user1", "openid", 1*time.Nanosecond)
	time.Sleep(2 * time.Millisecond)

	if s.ValidateAccessToken("at-expired") != nil {
		t.Error("expired access token should return nil")
	}
}

func TestAccessToken_NotFound(t *testing.T) {
	s := NewStore()
	if s.ValidateAccessToken("nonexistent") != nil {
		t.Error("expected nil for unknown token")
	}
}
