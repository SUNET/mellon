package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/masv3971/mellon/internal/config"
	opcrypto "github.com/masv3971/mellon/internal/crypto"
)

func TestHandleDiscovery(t *testing.T) {
	cfg := &config.Config{
		Issuer: "https://auth.example.com",
		Realm:  config.RealmConfig{Realm: "test", SigningAlgorithm: "RS256"},
	}
	handler := HandleDiscovery(cfg)

	// Use chi router context to provide realm param
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("realm", "test")
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp DiscoveryResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Issuer != "https://auth.example.com/realms/test" {
		t.Errorf("issuer = %q", resp.Issuer)
	}
	if !strings.Contains(resp.TokenEndpoint, "/token") {
		t.Errorf("token_endpoint = %q", resp.TokenEndpoint)
	}
	if !strings.Contains(resp.AuthorizationEndpoint, "/auth") {
		t.Errorf("authorization_endpoint = %q", resp.AuthorizationEndpoint)
	}
	if resp.IDTokenSigningAlgValuesSupported[0] != "RS256" {
		t.Errorf("id_token_signing_alg = %v", resp.IDTokenSigningAlgValuesSupported)
	}
}

func TestHandleDiscovery_NoRealmParam(t *testing.T) {
	cfg := &config.Config{
		Issuer: "https://auth.example.com",
		Realm:  config.RealmConfig{Realm: "default", SigningAlgorithm: "RS256"},
	}
	handler := HandleDiscovery(cfg)

	rctx := chi.NewRouteContext()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp DiscoveryResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Issuer != "https://auth.example.com/realms/default" {
		t.Errorf("issuer = %q", resp.Issuer)
	}
}

func TestHandleAuthorize(t *testing.T) {
	cfg, _, store := testSetup()
	cfg.Realm.Clients[0].RedirectURIs = []string{"http://localhost:3000/callback"}
	handler := HandleAuthorize(cfg, store)

	t.Run("valid request redirects to login", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=test-client&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid&state=xyz", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("status = %d, want 302", w.Code)
		}
		loc := w.Header().Get("Location")
		if !strings.Contains(loc, "/login") {
			t.Errorf("should redirect to login, got %q", loc)
		}
	})

	t.Run("unsupported response_type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=test-client&redirect_uri=http://localhost:3000/callback&response_type=token", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", w.Code)
		}
	})

	t.Run("invalid client", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=unknown&redirect_uri=http://localhost:3000/callback&response_type=code", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", w.Code)
		}
	})

	t.Run("invalid redirect uri", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=test-client&redirect_uri=http://evil.com/callback&response_type=code", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", w.Code)
		}
	})

	t.Run("code_challenge without method defaults to plain", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=test-client&redirect_uri=http://localhost:3000/callback&response_type=code&code_challenge=abc", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("status = %d, want 302", w.Code)
		}
	})
}

func TestValidateRedirectURI(t *testing.T) {
	client := &config.ClientConfig{
		RedirectURIs: []string{
			"http://localhost:3000/callback",
			"http://localhost:4000/*",
		},
	}

	tests := []struct {
		uri  string
		want bool
	}{
		{"http://localhost:3000/callback", true},
		{"http://localhost:4000/any/path", true},
		{"http://localhost:4000/", true},
		{"http://evil.com/callback", false},
		{"", false},
	}
	for _, tt := range tests {
		got := validateRedirectURI(client, tt.uri)
		if got != tt.want {
			t.Errorf("validateRedirectURI(%q) = %v, want %v", tt.uri, got, tt.want)
		}
	}
}

func TestCompleteAuthorize(t *testing.T) {
	cfg, _, store := testSetup()

	form := url.Values{
		"client_id":    {"test-client"},
		"redirect_uri": {"http://localhost:3000/callback"},
		"scope":        {"openid profile"},
		"state":        {"mystate"},
		"nonce":        {"mynonce"},
	}
	req := httptest.NewRequest(http.MethodPost, "/complete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CompleteAuthorize(w, req, cfg, store, "testuser")

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Error("expected code in redirect")
	}
	if loc.Query().Get("state") != "mystate" {
		t.Errorf("state = %q", loc.Query().Get("state"))
	}
}

func TestCompleteAuthorize_NoState(t *testing.T) {
	cfg, _, store := testSetup()

	form := url.Values{
		"client_id":    {"test-client"},
		"redirect_uri": {"http://localhost:3000/callback"},
		"scope":        {"openid"},
	}
	req := httptest.NewRequest(http.MethodPost, "/complete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CompleteAuthorize(w, req, cfg, store, "testuser")

	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("state") != "" {
		t.Error("state should be empty when not provided")
	}
}

func TestHandleIntrospect(t *testing.T) {
	cfg, kp, store := testSetup()

	t.Run("method not allowed", func(t *testing.T) {
		handler := HandleIntrospect(cfg, kp, store)
		req := httptest.NewRequest(http.MethodGet, "/introspect", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", w.Code)
		}
	})

	t.Run("missing client credentials", func(t *testing.T) {
		handler := HandleIntrospect(cfg, kp, store)
		form := url.Values{"token": {"some-token"}}
		req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", w.Code)
		}
	})

	t.Run("invalid client", func(t *testing.T) {
		handler := HandleIntrospect(cfg, kp, store)
		form := url.Values{"token": {"some-token"}}
		req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("wrong-client", "wrong-secret")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", w.Code)
		}
	})

	t.Run("empty token", func(t *testing.T) {
		handler := HandleIntrospect(cfg, kp, store)
		form := url.Values{}
		req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "test-secret")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		var resp IntrospectResponse
		json.NewDecoder(w.Body).Decode(&resp)
		if resp.Active {
			t.Error("empty token should be inactive")
		}
	})

	t.Run("valid access token", func(t *testing.T) {
		// Issue a real signed token and store it
		cfg.Realm.Clients[0].ServiceAccountsEnabled = true
		tokenHandler := HandleToken(cfg, kp, store)

		tokenForm := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {"test-client"},
			"client_secret": {"test-secret"},
		}
		tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
		tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		tokenW := httptest.NewRecorder()
		tokenHandler.ServeHTTP(tokenW, tokenReq)

		var tokenResp TokenResponse
		json.NewDecoder(tokenW.Body).Decode(&tokenResp)

		handler := HandleIntrospect(cfg, kp, store)
		form := url.Values{"token": {tokenResp.AccessToken}}
		req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "test-secret")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		var resp IntrospectResponse
		json.NewDecoder(w.Body).Decode(&resp)
		if !resp.Active {
			t.Error("valid token should be active")
		}
		if resp.TokenType != "Bearer" {
			t.Errorf("token_type = %q", resp.TokenType)
		}
	})

	t.Run("invalid jwt token", func(t *testing.T) {
		handler := HandleIntrospect(cfg, kp, store)
		form := url.Values{"token": {"not.a.jwt"}}
		req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "test-secret")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		var resp IntrospectResponse
		json.NewDecoder(w.Body).Decode(&resp)
		if resp.Active {
			t.Error("invalid jwt should be inactive")
		}
	})

	t.Run("valid refresh token", func(t *testing.T) {
		rt := store.CreateRefreshToken("test-client", "testuser", "openid", 30*time.Minute)

		handler := HandleIntrospect(cfg, kp, store)
		form := url.Values{"token": {rt}}
		req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "test-secret")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		var resp IntrospectResponse
		json.NewDecoder(w.Body).Decode(&resp)
		if !resp.Active {
			t.Error("valid refresh token should be active")
		}
		if resp.TokenType != "refresh_token" {
			t.Errorf("token_type = %q", resp.TokenType)
		}
	})
}

func TestHandleJWKS(t *testing.T) {
	kp, _ := opcrypto.GenerateKeyPair(opcrypto.RS256, "jwks-kid")
	handler := HandleJWKS(kp)

	req := httptest.NewRequest(http.MethodGet, "/certs", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var jwks opcrypto.JWKSet
	json.NewDecoder(w.Body).Decode(&jwks)
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].KID != "jwks-kid" {
		t.Errorf("kid = %q", jwks.Keys[0].KID)
	}
}

func TestHandleLogout(t *testing.T) {
	handler := HandleLogout()

	t.Run("redirect with post_logout_redirect_uri", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/logout?post_logout_redirect_uri=http://localhost:3000", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("status = %d, want 302", w.Code)
		}
		if w.Header().Get("Location") != "http://localhost:3000" {
			t.Errorf("Location = %q", w.Header().Get("Location"))
		}
	})

	t.Run("redirect with redirect_uri", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/logout?redirect_uri=https://example.com", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("status = %d, want 302", w.Code)
		}
	})

	t.Run("no redirect uri", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/logout", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Logged out") {
			t.Error("expected 'Logged out' message")
		}
	})

	t.Run("invalid redirect uri scheme", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/logout?post_logout_redirect_uri=ftp://evil.com", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want 200 for invalid scheme", w.Code)
		}
	})
}
