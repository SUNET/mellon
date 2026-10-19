package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/masv3971/mellon/internal/config"
	opcrypto "github.com/masv3971/mellon/internal/crypto"
	"github.com/masv3971/mellon/internal/session"
)

const (
	goodOrigin = "http://localhost:3000"
	evilOrigin = "http://evil.example"
)

func corsSetup() (*config.Config, *opcrypto.KeyPair, *session.Store) {
	cfg, kp, store := testSetup()
	cfg.Realm.Clients[0].WebOrigins = []string{goodOrigin}
	cfg.Realm.Clients[0].DirectAccessGrantsEnabled = true
	cfg.Realm.Clients[0].ServiceAccountsEnabled = true
	return cfg, kp, store
}

func assertACAO(t *testing.T, w *httptest.ResponseRecorder, want string) {
	t.Helper()
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != want {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, want)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want empty", got)
	}
	if !strings.Contains(strings.Join(w.Header().Values("Vary"), ","), "Origin") {
		t.Errorf("Vary header missing Origin: %v", w.Header().Values("Vary"))
	}
}

func passwordGrantRequest(origin, password string) *http.Request {
	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"username":      {"testuser"},
		"password":      {password},
		"scope":         {"openid profile email"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return req
}

func TestOriginAllowed(t *testing.T) {
	tests := []struct {
		origin  string
		allowed []string
		want    bool
	}{
		{goodOrigin, []string{goodOrigin}, true},
		{evilOrigin, []string{goodOrigin}, false},
		{evilOrigin, []string{"*"}, true},
		{"", []string{"*"}, false},
		{goodOrigin, nil, false},
		{goodOrigin + "/", []string{goodOrigin}, false},
	}
	for _, tt := range tests {
		if got := originAllowed(tt.origin, tt.allowed); got != tt.want {
			t.Errorf("originAllowed(%q, %v) = %v, want %v", tt.origin, tt.allowed, got, tt.want)
		}
	}
}

func TestHandlePreflight(t *testing.T) {
	handler := HandlePreflight("POST, OPTIONS")

	t.Run("with origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/token", nil)
		req.Header.Set("Origin", evilOrigin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("status = %d, want 204", w.Code)
		}
		assertACAO(t, w, evilOrigin)
		if got := w.Header().Get("Access-Control-Allow-Methods"); got != "POST, OPTIONS" {
			t.Errorf("Allow-Methods = %q", got)
		}
		if got := w.Header().Get("Access-Control-Allow-Headers"); got != "Authorization, Content-Type" {
			t.Errorf("Allow-Headers = %q", got)
		}
		if got := w.Header().Get("Access-Control-Max-Age"); got != "3600" {
			t.Errorf("Max-Age = %q", got)
		}
	})

	t.Run("without origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/token", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("status = %d, want 204", w.Code)
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("Access-Control-Allow-Origin = %q, want empty", got)
		}
	})
}

func TestHandleToken_CORS(t *testing.T) {
	t.Run("allowed origin", func(t *testing.T) {
		cfg, kp, store := corsSetup()
		w := httptest.NewRecorder()
		HandleToken(cfg, kp, store).ServeHTTP(w, passwordGrantRequest(goodOrigin, "password"))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		assertACAO(t, w, goodOrigin)
	})

	t.Run("allowed origin on error", func(t *testing.T) {
		cfg, kp, store := corsSetup()
		w := httptest.NewRecorder()
		HandleToken(cfg, kp, store).ServeHTTP(w, passwordGrantRequest(goodOrigin, "wrong"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		assertACAO(t, w, goodOrigin)
	})

	t.Run("disallowed origin", func(t *testing.T) {
		cfg, kp, store := corsSetup()
		w := httptest.NewRecorder()
		HandleToken(cfg, kp, store).ServeHTTP(w, passwordGrantRequest(evilOrigin, "password"))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		assertACAO(t, w, "")
	})

	t.Run("no origin", func(t *testing.T) {
		cfg, kp, store := corsSetup()
		w := httptest.NewRecorder()
		HandleToken(cfg, kp, store).ServeHTTP(w, passwordGrantRequest("", "password"))
		assertACAO(t, w, "")
	})

	t.Run("wildcard web origin", func(t *testing.T) {
		cfg, kp, store := corsSetup()
		cfg.Realm.Clients[0].WebOrigins = []string{"*"}
		w := httptest.NewRecorder()
		HandleToken(cfg, kp, store).ServeHTTP(w, passwordGrantRequest(evilOrigin, "password"))
		assertACAO(t, w, evilOrigin)
	})

	t.Run("plus web origin", func(t *testing.T) {
		cfg, kp, store := corsSetup()
		cfg.Realm.Clients[0].WebOrigins = []string{"+"}
		w := httptest.NewRecorder()
		HandleToken(cfg, kp, store).ServeHTTP(w, passwordGrantRequest(goodOrigin, "password"))
		assertACAO(t, w, goodOrigin)
	})

	t.Run("unknown client", func(t *testing.T) {
		cfg, kp, store := corsSetup()
		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {"unknown"},
			"client_secret": {"x"},
		}
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", goodOrigin)
		w := httptest.NewRecorder()
		HandleToken(cfg, kp, store).ServeHTTP(w, req)
		assertACAO(t, w, "")
	})
}

func TestAccessToken_AllowedOriginsClaim(t *testing.T) {
	decode := func(t *testing.T, kp *opcrypto.KeyPair, w *httptest.ResponseRecorder) jwt.MapClaims {
		t.Helper()
		var resp TokenResponse
		json.NewDecoder(w.Body).Decode(&resp)
		tok, err := kp.ValidateToken(resp.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		return tok.Claims.(jwt.MapClaims)
	}

	t.Run("present", func(t *testing.T) {
		cfg, kp, store := corsSetup()
		w := httptest.NewRecorder()
		HandleToken(cfg, kp, store).ServeHTTP(w, passwordGrantRequest("", "password"))
		claims := decode(t, kp, w)
		got, ok := claims["allowed-origins"].([]any)
		if !ok || len(got) != 1 || got[0] != goodOrigin {
			t.Errorf("allowed-origins = %v", claims["allowed-origins"])
		}
	})

	t.Run("client credentials", func(t *testing.T) {
		cfg, kp, store := corsSetup()
		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {"test-client"},
			"client_secret": {"test-secret"},
		}
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		HandleToken(cfg, kp, store).ServeHTTP(w, req)
		claims := decode(t, kp, w)
		if _, ok := claims["allowed-origins"]; !ok {
			t.Error("expected allowed-origins claim")
		}
	})

	t.Run("absent", func(t *testing.T) {
		cfg, kp, store := corsSetup()
		cfg.Realm.Clients[0].WebOrigins = nil
		w := httptest.NewRecorder()
		HandleToken(cfg, kp, store).ServeHTTP(w, passwordGrantRequest("", "password"))
		claims := decode(t, kp, w)
		if _, ok := claims["allowed-origins"]; ok {
			t.Errorf("unexpected allowed-origins = %v", claims["allowed-origins"])
		}
	})
}

func TestHandleUserInfo_CORS(t *testing.T) {
	issue := func(t *testing.T, cfg *config.Config, kp *opcrypto.KeyPair, store *session.Store) string {
		t.Helper()
		w := httptest.NewRecorder()
		HandleToken(cfg, kp, store).ServeHTTP(w, passwordGrantRequest("", "password"))
		var resp TokenResponse
		json.NewDecoder(w.Body).Decode(&resp)
		if resp.AccessToken == "" {
			t.Fatal("no access token")
		}
		return resp.AccessToken
	}
	userinfo := func(cfg *config.Config, kp *opcrypto.KeyPair, store *session.Store, token, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		HandleUserInfo(cfg, kp, store).ServeHTTP(w, req)
		return w
	}

	t.Run("allowed origin", func(t *testing.T) {
		cfg, kp, store := corsSetup()
		w := userinfo(cfg, kp, store, issue(t, cfg, kp, store), goodOrigin)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		assertACAO(t, w, goodOrigin)
	})

	t.Run("disallowed origin", func(t *testing.T) {
		cfg, kp, store := corsSetup()
		w := userinfo(cfg, kp, store, issue(t, cfg, kp, store), evilOrigin)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		assertACAO(t, w, "")
	})

	t.Run("missing token readable from any origin", func(t *testing.T) {
		cfg, kp, store := corsSetup()
		w := userinfo(cfg, kp, store, "", evilOrigin)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		assertACAO(t, w, evilOrigin)
	})

	t.Run("invalid token readable from any origin", func(t *testing.T) {
		cfg, kp, store := corsSetup()
		w := userinfo(cfg, kp, store, "bogus", evilOrigin)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		assertACAO(t, w, evilOrigin)
	})

	t.Run("opaque stored token falls back to client origins", func(t *testing.T) {
		cfg, kp, store := corsSetup()
		store.StoreAccessToken("opaque", "test-client", "testuser", "openid", 5*time.Minute)
		assertACAO(t, userinfo(cfg, kp, store, "opaque", goodOrigin), goodOrigin)
		assertACAO(t, userinfo(cfg, kp, store, "opaque", evilOrigin), "")
	})
}

func TestPublicEndpoints_CORS(t *testing.T) {
	cfg, kp, _ := corsSetup()

	for name, h := range map[string]http.Handler{
		"discovery": HandleDiscovery(cfg),
		"jwks":      HandleJWKS(kp),
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Origin", evilOrigin)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			assertACAO(t, w, evilOrigin)
		})
	}
}
