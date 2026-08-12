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

func testSetup() (*config.Config, *opcrypto.KeyPair, *session.Store) {
	cfg := &config.Config{
		Issuer: "http://localhost:8080",
		Realm: config.RealmConfig{
			Realm:                "test",
			AccessTokenLifespan:  300,
			RefreshTokenLifespan: 1800,
			AccessCodeLifespan:   60,
			Clients: []config.ClientConfig{
				{
					ClientID:            "test-client",
					Secret:              "test-secret",
					RedirectURIs:        []string{"http://localhost:3000/callback"},
					StandardFlowEnabled: true,
					DefaultClientScopes: []string{"openid", "profile", "email"},
					ProtocolMappers: []config.ProtocolMapperConfig{
						{
							Name:           "birthdate",
							Protocol:       "openid-connect",
							ProtocolMapper: "oidc-usermodel-attribute-mapper",
							Config: map[string]string{
								"user.attribute":       "birthdate",
								"claim.name":           "birthdate",
								"id.token.claim":       "true",
								"access.token.claim":   "true",
								"userinfo.token.claim": "true",
							},
						},
					},
				},
			},
			Users: []config.UserConfig{
				{
					Username:      "testuser",
					Email:         "test@example.com",
					EmailVerified: true,
					FirstName:     "Test",
					LastName:      "User",
					Enabled:       true,
					Credentials:   []config.CredentialConfig{{Type: "password", Value: "password"}},
					Attributes:    map[string][]string{"birthdate": {"1990-01-15"}},
				},
			},
		},
	}
	kp, _ := opcrypto.GenerateKeyPair(opcrypto.RS256, "test-kid")
	store := session.NewStore()
	return cfg, kp, store
}

func TestHandleUserInfo_NoBearerToken(t *testing.T) {
	cfg, kp, store := testSetup()
	handler := HandleUserInfo(cfg, kp, store)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestHandleUserInfo_InvalidToken(t *testing.T) {
	cfg, kp, store := testSetup()
	handler := HandleUserInfo(cfg, kp, store)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestHandleUserInfo_UserNotFound(t *testing.T) {
	cfg, kp, store := testSetup()
	store.StoreAccessToken("valid-token", "test-client", "nonexistent", "openid profile email", 5*time.Minute)
	handler := HandleUserInfo(cfg, kp, store)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleUserInfo_Success(t *testing.T) {
	cfg, kp, store := testSetup()
	store.StoreAccessToken("valid-token", "test-client", "testuser", "openid profile email", 5*time.Minute)
	handler := HandleUserInfo(cfg, kp, store)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["sub"] != "testuser" {
		t.Errorf("sub = %v", resp["sub"])
	}
	if resp["email"] != "test@example.com" {
		t.Errorf("email = %v", resp["email"])
	}
	if resp["given_name"] != "Test" {
		t.Errorf("given_name = %v", resp["given_name"])
	}
	if resp["family_name"] != "User" {
		t.Errorf("family_name = %v", resp["family_name"])
	}
	if resp["birthdate"] != "1990-01-15" {
		t.Errorf("birthdate = %v, want 1990-01-15", resp["birthdate"])
	}
}

func TestHandleUserInfo_ProfileScopeOnly(t *testing.T) {
	cfg, kp, store := testSetup()
	store.StoreAccessToken("token", "test-client", "testuser", "openid profile", 5*time.Minute)
	handler := HandleUserInfo(cfg, kp, store)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["given_name"] != "Test" {
		t.Errorf("given_name = %v", resp["given_name"])
	}
	if _, ok := resp["email"]; ok {
		t.Error("email should not be present without email scope")
	}
}

func TestHandleToken_MethodNotAllowed(t *testing.T) {
	cfg, kp, store := testSetup()
	handler := HandleToken(cfg, kp, store)

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandleToken_UnsupportedGrantType(t *testing.T) {
	cfg, kp, store := testSetup()
	handler := HandleToken(cfg, kp, store)

	form := url.Values{"grant_type": {"urn:unsupported"}}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleToken_ClientCredentials(t *testing.T) {
	cfg, kp, store := testSetup()
	cfg.Realm.Clients[0].ServiceAccountsEnabled = true
	handler := HandleToken(cfg, kp, store)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp TokenResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.AccessToken == "" {
		t.Error("expected access token")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q", resp.TokenType)
	}
}

func TestHandleToken_ClientCredentials_InvalidClient(t *testing.T) {
	cfg, kp, store := testSetup()
	handler := HandleToken(cfg, kp, store)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client"},
		"client_secret": {"wrong-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestHandleToken_ClientCredentials_NotAuthorized(t *testing.T) {
	cfg, kp, store := testSetup()
	cfg.Realm.Clients[0].ServiceAccountsEnabled = false
	handler := HandleToken(cfg, kp, store)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleToken_PasswordGrant(t *testing.T) {
	cfg, kp, store := testSetup()
	cfg.Realm.Clients[0].DirectAccessGrantsEnabled = true
	handler := HandleToken(cfg, kp, store)

	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"username":      {"testuser"},
		"password":      {"password"},
		"scope":         {"openid profile"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp TokenResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.AccessToken == "" {
		t.Error("expected access token")
	}
	if resp.IDToken == "" {
		t.Error("expected id token")
	}
}

func TestHandleToken_PasswordGrant_InvalidCredentials(t *testing.T) {
	cfg, kp, store := testSetup()
	cfg.Realm.Clients[0].DirectAccessGrantsEnabled = true
	handler := HandleToken(cfg, kp, store)

	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"username":      {"testuser"},
		"password":      {"wrong"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestHandleToken_PasswordGrant_NotEnabled(t *testing.T) {
	cfg, kp, store := testSetup()
	cfg.Realm.Clients[0].DirectAccessGrantsEnabled = false
	handler := HandleToken(cfg, kp, store)

	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"username":      {"testuser"},
		"password":      {"password"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleToken_AuthCodeGrant(t *testing.T) {
	cfg, kp, store := testSetup()
	handler := HandleToken(cfg, kp, store)

	code := store.CreateCode("test-client", "http://localhost:3000/callback", "openid profile email", "nonce123", "testuser", "", "", 60*time.Second)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp TokenResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.AccessToken == "" {
		t.Error("expected access token")
	}
	if resp.IDToken == "" {
		t.Error("expected id token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected refresh token")
	}
}

func TestHandleToken_AuthCodeGrant_InvalidCode(t *testing.T) {
	cfg, kp, store := testSetup()
	handler := HandleToken(cfg, kp, store)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"bad-code"},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleToken_AuthCodeGrant_RedirectMismatch(t *testing.T) {
	cfg, kp, store := testSetup()
	handler := HandleToken(cfg, kp, store)

	code := store.CreateCode("test-client", "http://localhost:3000/callback", "openid", "", "testuser", "", "", 60*time.Second)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://evil.com/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleToken_AuthCodeGrant_MissingClientCreds(t *testing.T) {
	cfg, kp, store := testSetup()
	handler := HandleToken(cfg, kp, store)

	form := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"some-code"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestHandleToken_RefreshTokenGrant(t *testing.T) {
	cfg, kp, store := testSetup()
	handler := HandleToken(cfg, kp, store)

	rt := store.CreateRefreshToken("test-client", "testuser", "openid profile", 30*time.Minute)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp TokenResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.AccessToken == "" {
		t.Error("expected access token")
	}
}

func TestHandleToken_RefreshTokenGrant_InvalidToken(t *testing.T) {
	cfg, kp, store := testSetup()
	handler := HandleToken(cfg, kp, store)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"invalid"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleToken_BasicAuth(t *testing.T) {
	cfg, kp, store := testSetup()
	cfg.Realm.Clients[0].ServiceAccountsEnabled = true
	handler := HandleToken(cfg, kp, store)

	form := url.Values{"grant_type": {"client_credentials"}}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("test-client", "test-secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandleToken_IDTokenContainsExtraClaims(t *testing.T) {
	cfg, kp, store := testSetup()
	handler := HandleToken(cfg, kp, store)

	code := store.CreateCode("test-client", "http://localhost:3000/callback", "openid profile", "", "testuser", "", "", 60*time.Second)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp TokenResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// Parse and verify the ID token contains the birthdate claim
	tok, err := kp.ValidateToken(resp.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	claims := tok.Claims.(jwt.MapClaims)
	if claims["birthdate"] != "1990-01-15" {
		t.Errorf("id_token birthdate = %v, want 1990-01-15", claims["birthdate"])
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"Bearer abc123", "abc123"},
		{"Bearer ", ""},
		{"Basic abc", ""},
		{"", ""},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if tt.header != "" {
			req.Header.Set("Authorization", tt.header)
		}
		got := extractBearerToken(req)
		if got != tt.want {
			t.Errorf("extractBearerToken(%q) = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func TestUserInfoResponse_MarshalJSON(t *testing.T) {
	t.Run("with extra", func(t *testing.T) {
		resp := UserInfoResponse{
			Sub:   "user1",
			Email: "user@example.com",
			Extra: map[string]any{
				"birthdate": "1990-01-15",
				"custom":    42,
			},
		}
		data, err := resp.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}

		var m map[string]any
		json.Unmarshal(data, &m)

		if m["sub"] != "user1" {
			t.Errorf("sub = %v", m["sub"])
		}
		if m["birthdate"] != "1990-01-15" {
			t.Errorf("birthdate = %v", m["birthdate"])
		}
	})

	t.Run("without extra", func(t *testing.T) {
		resp := UserInfoResponse{Sub: "user1"}
		data, err := resp.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		json.Unmarshal(data, &m)
		if m["sub"] != "user1" {
			t.Errorf("sub = %v", m["sub"])
		}
	})

	t.Run("extra does not override standard", func(t *testing.T) {
		resp := UserInfoResponse{
			Sub:   "real",
			Extra: map[string]any{"sub": "fake"},
		}
		data, _ := resp.MarshalJSON()
		var m map[string]any
		json.Unmarshal(data, &m)
		if m["sub"] != "real" {
			t.Errorf("sub should not be overridden: got %v", m["sub"])
		}
	})
}
