package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/masv3971/mellon/internal/config"
	opcrypto "github.com/masv3971/mellon/internal/crypto"
	"github.com/masv3971/mellon/internal/session"
)

var audAPIMapper = config.ProtocolMapperConfig{
	Name:           "aud-api",
	Protocol:       "openid-connect",
	ProtocolMapper: "oidc-audience-mapper",
	Config: map[string]string{
		"included.custom.audience": "api",
		"access.token.claim":       "true",
	},
}

// scopeSetup returns the shared test setup with an optional client scope
// and grant types enabled.
func scopeSetup() (*config.Config, *opcrypto.KeyPair, *session.Store) {
	cfg, kp, store := testSetup()
	c := &cfg.Realm.Clients[0]
	c.DirectAccessGrantsEnabled = true
	c.ServiceAccountsEnabled = true
	c.OptionalClientScopes = []string{"offline_access", "phone"}
	return cfg, kp, store
}

func postToken(t *testing.T, cfg *config.Config, kp *opcrypto.KeyPair, store *session.Store, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	HandleToken(cfg, kp, store).ServeHTTP(w, req)
	return w
}

func passwordForm(scope string) url.Values {
	f := url.Values{
		"grant_type":    {"password"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"username":      {"testuser"},
		"password":      {"password"},
	}
	if scope != "" {
		f.Set("scope", scope)
	}
	return f
}

func clientCredentialsForm(scope string) url.Values {
	f := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	if scope != "" {
		f.Set("scope", scope)
	}
	return f
}

func decodeTokenResponse(t *testing.T, w *httptest.ResponseRecorder) TokenResponse {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func parseClaims(t *testing.T, kp *opcrypto.KeyPair, token string) jwt.MapClaims {
	t.Helper()
	tok, err := kp.ValidateToken(token)
	if err != nil {
		t.Fatal(err)
	}
	return tok.Claims.(jwt.MapClaims)
}

func audience(t *testing.T, c jwt.MapClaims) []string {
	t.Helper()
	aud, err := c.GetAudience()
	if err != nil {
		t.Fatal(err)
	}
	return aud
}

func assertTokenError(t *testing.T, w *httptest.ResponseRecorder, code string) {
	t.Helper()
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", w.Code, w.Body.String())
	}
	var e TokenError
	json.NewDecoder(w.Body).Decode(&e)
	if e.Error != code {
		t.Errorf("error = %q, want %q", e.Error, code)
	}
}

func TestToken_InvalidScope(t *testing.T) {
	cfg, kp, store := scopeSetup()

	t.Run("password", func(t *testing.T) {
		w := postToken(t, cfg, kp, store, passwordForm("openid admin"))
		assertTokenError(t, w, "invalid_scope")
	})
	t.Run("client_credentials", func(t *testing.T) {
		w := postToken(t, cfg, kp, store, clientCredentialsForm("admin"))
		assertTokenError(t, w, "invalid_scope")
	})
}

func TestToken_GrantedScopes(t *testing.T) {
	cfg, kp, store := scopeSetup()

	t.Run("defaults always granted, optional on request", func(t *testing.T) {
		resp := decodeTokenResponse(t, postToken(t, cfg, kp, store, passwordForm("openid phone")))
		if resp.Scope != "openid profile email phone" {
			t.Errorf("scope = %q", resp.Scope)
		}
		claims := parseClaims(t, kp, resp.AccessToken)
		if claims["scope"] != "openid profile email phone" {
			t.Errorf("scope claim = %v", claims["scope"])
		}
	})

	t.Run("optional not granted unless requested", func(t *testing.T) {
		resp := decodeTokenResponse(t, postToken(t, cfg, kp, store, passwordForm("openid")))
		if resp.Scope != "openid profile email" {
			t.Errorf("scope = %q", resp.Scope)
		}
	})

	t.Run("no id_token without openid", func(t *testing.T) {
		resp := decodeTokenResponse(t, postToken(t, cfg, kp, store, passwordForm("")))
		if resp.IDToken != "" {
			t.Error("unexpected id_token")
		}
		if resp.Scope != "profile email" {
			t.Errorf("scope = %q", resp.Scope)
		}
	})

	t.Run("client_credentials gets defaults and no refresh token", func(t *testing.T) {
		resp := decodeTokenResponse(t, postToken(t, cfg, kp, store, clientCredentialsForm("")))
		if resp.Scope != "profile email" {
			t.Errorf("scope = %q", resp.Scope)
		}
		if resp.RefreshToken != "" {
			t.Error("client_credentials must not return a refresh token")
		}
	})
}

func TestToken_AudienceMapper(t *testing.T) {
	t.Run("absent without mapper", func(t *testing.T) {
		cfg, kp, store := scopeSetup()
		resp := decodeTokenResponse(t, postToken(t, cfg, kp, store, clientCredentialsForm("")))
		claims := parseClaims(t, kp, resp.AccessToken)
		if _, ok := claims["aud"]; ok {
			t.Errorf("aud = %v, want absent", claims["aud"])
		}
		if claims["azp"] != "test-client" {
			t.Errorf("azp = %v", claims["azp"])
		}
		if claims["typ"] != "Bearer" {
			t.Errorf("typ = %v", claims["typ"])
		}
	})

	for name, form := range map[string]url.Values{
		"client_credentials": clientCredentialsForm(""),
		"password":           passwordForm("openid"),
	} {
		t.Run(name, func(t *testing.T) {
			cfg, kp, store := scopeSetup()
			c := &cfg.Realm.Clients[0]
			c.ProtocolMappers = append(c.ProtocolMappers, audAPIMapper)

			resp := decodeTokenResponse(t, postToken(t, cfg, kp, store, form))
			claims := parseClaims(t, kp, resp.AccessToken)
			if got := audience(t, claims); !reflect.DeepEqual(got, []string{"api"}) {
				t.Errorf("access aud = %v, want [api]", got)
			}
			if claims["azp"] != "test-client" {
				t.Errorf("azp = %v", claims["azp"])
			}
			if resp.IDToken != "" {
				id := parseClaims(t, kp, resp.IDToken)
				if got := audience(t, id); !reflect.DeepEqual(got, []string{"test-client"}) {
					t.Errorf("id aud = %v, want [test-client]", got)
				}
				if id["typ"] != "ID" {
					t.Errorf("id typ = %v", id["typ"])
				}
			}
		})
	}

	t.Run("id.token.claim adds to id_token aud", func(t *testing.T) {
		cfg, kp, store := scopeSetup()
		m := audAPIMapper
		m.Config = map[string]string{"included.custom.audience": "api", "access.token.claim": "true", "id.token.claim": "true"}
		c := &cfg.Realm.Clients[0]
		c.ProtocolMappers = append(c.ProtocolMappers, m)

		resp := decodeTokenResponse(t, postToken(t, cfg, kp, store, passwordForm("openid")))
		id := parseClaims(t, kp, resp.IDToken)
		if got := audience(t, id); !reflect.DeepEqual(got, []string{"test-client", "api"}) {
			t.Errorf("id aud = %v", got)
		}
	})

	t.Run("mapper on optional client scope", func(t *testing.T) {
		cfg, kp, store := scopeSetup()
		cfg.Realm.ClientScopes = []config.ClientScopeConfig{
			{Name: "profile"}, {Name: "email"},
			{Name: "api.read", Protocol: "openid-connect", ProtocolMappers: []config.ProtocolMapperConfig{audAPIMapper}},
		}
		cfg.Realm.Clients[0].OptionalClientScopes = []string{"api.read"}

		resp := decodeTokenResponse(t, postToken(t, cfg, kp, store, clientCredentialsForm("")))
		if _, ok := parseClaims(t, kp, resp.AccessToken)["aud"]; ok {
			t.Error("aud should be absent without api.read")
		}

		resp = decodeTokenResponse(t, postToken(t, cfg, kp, store, clientCredentialsForm("api.read")))
		if got := audience(t, parseClaims(t, kp, resp.AccessToken)); !reflect.DeepEqual(got, []string{"api"}) {
			t.Errorf("aud = %v", got)
		}
		if resp.Scope != "profile email api.read" {
			t.Errorf("scope = %q", resp.Scope)
		}
	})
}

func TestToken_ClaimGating(t *testing.T) {
	cfg, kp, store := scopeSetup()
	cfg.Realm.Clients[0].DefaultClientScopes = []string{}
	cfg.Realm.Clients[0].OptionalClientScopes = []string{"profile", "email"}

	t.Run("no profile/email", func(t *testing.T) {
		resp := decodeTokenResponse(t, postToken(t, cfg, kp, store, passwordForm("openid")))
		for _, tok := range []string{resp.AccessToken, resp.IDToken} {
			c := parseClaims(t, kp, tok)
			for _, k := range []string{"email", "email_verified", "name", "given_name", "family_name", "preferred_username"} {
				if _, ok := c[k]; ok {
					t.Errorf("unexpected claim %s = %v", k, c[k])
				}
			}
		}
	})

	t.Run("profile and email", func(t *testing.T) {
		resp := decodeTokenResponse(t, postToken(t, cfg, kp, store, passwordForm("openid profile email")))
		for _, tok := range []string{resp.AccessToken, resp.IDToken} {
			c := parseClaims(t, kp, tok)
			if c["email"] != "test@example.com" || c["given_name"] != "Test" || c["preferred_username"] != "testuser" {
				t.Errorf("claims = %v", c)
			}
		}
	})
}

func TestToken_RefreshScope(t *testing.T) {
	cfg, kp, store := scopeSetup()

	refresh := func(rt, scope string) *httptest.ResponseRecorder {
		f := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {rt},
			"client_id":     {"test-client"},
			"client_secret": {"test-secret"},
		}
		if scope != "" {
			f.Set("scope", scope)
		}
		return postToken(t, cfg, kp, store, f)
	}

	t.Run("keeps original grant", func(t *testing.T) {
		rt := store.CreateRefreshToken("test-client", "testuser", "openid profile email phone", 30*time.Minute)
		resp := decodeTokenResponse(t, refresh(rt, ""))
		if resp.Scope != "openid profile email phone" {
			t.Errorf("scope = %q", resp.Scope)
		}
	})

	t.Run("narrows", func(t *testing.T) {
		rt := store.CreateRefreshToken("test-client", "testuser", "openid profile email phone", 30*time.Minute)
		resp := decodeTokenResponse(t, refresh(rt, "openid"))
		if resp.Scope != "openid profile email" {
			t.Errorf("scope = %q", resp.Scope)
		}
		if resp.IDToken == "" {
			t.Error("expected id_token")
		}
	})

	t.Run("cannot widen", func(t *testing.T) {
		rt := store.CreateRefreshToken("test-client", "testuser", "openid profile email", 30*time.Minute)
		assertTokenError(t, refresh(rt, "openid phone"), "invalid_scope")
		// The refresh token must not be consumed by a rejected request.
		decodeTokenResponse(t, refresh(rt, ""))
	})
}

func TestToken_AuthCodeClientMismatch(t *testing.T) {
	cfg, kp, store := scopeSetup()
	cfg.Realm.Clients = append(cfg.Realm.Clients, config.ClientConfig{ClientID: "other", Secret: "s"})
	code := store.CreateCode("test-client", "http://localhost:3000/callback", "openid", "", "testuser", "", "", time.Minute)

	w := postToken(t, cfg, kp, store, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {"other"},
		"client_secret": {"s"},
	})
	assertTokenError(t, w, "invalid_grant")
}

func TestAuthorize_InvalidScope(t *testing.T) {
	cfg, _, store := scopeSetup()
	req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=test-client&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid+admin&state=s1", nil)
	w := httptest.NewRecorder()
	HandleAuthorize(cfg, store).ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Host != "localhost:3000" || loc.Query().Get("error") != "invalid_scope" || loc.Query().Get("state") != "s1" {
		t.Errorf("Location = %s", loc)
	}
}

func TestCompleteAuthorize_StoresGrantedScopes(t *testing.T) {
	cfg, kp, store := scopeSetup()
	cfg.Realm.Clients[0].ProtocolMappers = append(cfg.Realm.Clients[0].ProtocolMappers, audAPIMapper)

	form := url.Values{
		"client_id":    {"test-client"},
		"redirect_uri": {"http://localhost:3000/callback"},
		"scope":        {"openid phone"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	CompleteAuthorize(w, req, cfg, store, "testuser")

	loc, _ := url.Parse(w.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("Location = %s", loc)
	}

	resp := decodeTokenResponse(t, postToken(t, cfg, kp, store, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}))
	if resp.Scope != "openid profile email phone" {
		t.Errorf("scope = %q", resp.Scope)
	}
	if resp.RefreshToken == "" {
		t.Error("expected refresh token")
	}
	if got := audience(t, parseClaims(t, kp, resp.AccessToken)); !reflect.DeepEqual(got, []string{"api"}) {
		t.Errorf("aud = %v", got)
	}
}

func TestCompleteAuthorize_Revalidates(t *testing.T) {
	cfg, _, store := scopeSetup()
	tests := map[string]url.Values{
		"unknown client": {"client_id": {"nope"}, "redirect_uri": {"http://localhost:3000/callback"}},
		"bad redirect":   {"client_id": {"test-client"}, "redirect_uri": {"http://evil.example/cb"}},
	}
	for name, form := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			CompleteAuthorize(w, req, cfg, store, "testuser")
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", w.Code)
			}
		})
	}

	t.Run("invalid scope", func(t *testing.T) {
		form := url.Values{"client_id": {"test-client"}, "redirect_uri": {"http://localhost:3000/callback"}, "scope": {"admin"}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		CompleteAuthorize(w, req, cfg, store, "testuser")
		loc, _ := url.Parse(w.Header().Get("Location"))
		if loc.Query().Get("error") != "invalid_scope" || loc.Query().Get("code") != "" {
			t.Errorf("Location = %s", loc)
		}
	})
}

func TestIntrospect_AudAzpTyp(t *testing.T) {
	cfg, kp, store := scopeSetup()
	cfg.Realm.Clients[0].ProtocolMappers = append(cfg.Realm.Clients[0].ProtocolMappers, audAPIMapper)
	resp := decodeTokenResponse(t, postToken(t, cfg, kp, store, clientCredentialsForm("")))

	form := url.Values{"token": {resp.AccessToken}}
	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("test-client", "test-secret")
	w := httptest.NewRecorder()
	HandleIntrospect(cfg, kp, store).ServeHTTP(w, req)

	var ir IntrospectResponse
	json.NewDecoder(w.Body).Decode(&ir)
	if !ir.Active || !reflect.DeepEqual([]string(ir.Aud), []string{"api"}) || ir.Azp != "test-client" || ir.Typ != "Bearer" {
		t.Errorf("introspection = %+v", ir)
	}
	if ir.Scope != "profile email" {
		t.Errorf("scope = %q", ir.Scope)
	}
}

func TestUserInfo_ScopeMappersAndGating(t *testing.T) {
	cfg, kp, store := scopeSetup()
	store.StoreAccessToken("tok", "test-client", "testuser", "openid", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	HandleUserInfo(cfg, kp, store).ServeHTTP(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["sub"] != "testuser" {
		t.Errorf("sub = %v", resp["sub"])
	}
	for _, k := range []string{"preferred_username", "email", "given_name"} {
		if _, ok := resp[k]; ok {
			t.Errorf("unexpected %s", k)
		}
	}
}
