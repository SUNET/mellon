package oidc

import (
	"net/url"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/masv3971/mellon/internal/config"
	opcrypto "github.com/masv3971/mellon/internal/crypto"
	"github.com/masv3971/mellon/internal/session"
)

// loadRealm loads a real realm export from testdata (see testdata/README.md).
func loadRealm(t *testing.T, name string) (*config.Config, *opcrypto.KeyPair, *session.Store) {
	t.Helper()
	cfg, err := config.Load(filepath.Join("..", "..", "testdata", name), nil)
	if err != nil {
		t.Fatalf("Load(%s): %v", name, err)
	}
	cfg.Issuer = "http://localhost:8080"
	kp, err := opcrypto.GenerateKeyPair(opcrypto.RS256, "test-kid")
	if err != nil {
		t.Fatal(err)
	}
	return cfg, kp, session.NewStore()
}

func clientCredentials(id, secret, scope string) url.Values {
	f := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}}
	if scope != "" {
		f.Set("scope", scope)
	}
	return f
}

// Keycloak's own testsuite realm: the custom-audience client adds a custom
// "foo-bar" audience to both access and ID tokens.
func TestRealm_KeycloakTestRealm_CustomAudience(t *testing.T) {
	cfg, kp, store := loadRealm(t, "arquillian-testrealm.json")

	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {"custom-audience"},
		"client_secret": {"password"},
		"username":      {"test-user@localhost"},
		"password":      {"password"},
		"scope":         {"openid"},
	}
	resp := decodeTokenResponse(t, postToken(t, cfg, kp, store, form))

	if resp.Scope != "openid profile email" {
		t.Errorf("scope = %q", resp.Scope)
	}
	at := parseClaims(t, kp, resp.AccessToken)
	if got := audience(t, at); !reflect.DeepEqual(got, []string{"foo-bar"}) {
		t.Errorf("access aud = %v", got)
	}
	if at["azp"] != "custom-audience" || at["given_name"] != "Tom" || at["email"] != "test-user@localhost" {
		t.Errorf("access claims = %v", at)
	}
	id := parseClaims(t, kp, resp.IDToken)
	if got := audience(t, id); !reflect.DeepEqual(got, []string{"custom-audience", "foo-bar"}) {
		t.Errorf("id aud = %v", got)
	}

	// The client has no optionalClientScopes key, so it inherits the
	// built-in optional scopes (phone, address, ...) like a Keycloak import.
	form.Set("scope", "openid phone")
	if resp := decodeTokenResponse(t, postToken(t, cfg, kp, store, form)); resp.Scope != "openid profile email phone" {
		t.Errorf("scope = %q", resp.Scope)
	}

	form.Set("scope", "openid admin")
	assertTokenError(t, postToken(t, cfg, kp, store, form), "invalid_scope")
}

// Token-exchange realm: most granted default scopes are hidden from the
// scope claim and the audience comes from included.client.audience.
func TestRealm_TokenExchange(t *testing.T) {
	cfg, kp, store := loadRealm(t, "token-exchange-v2.json")

	t.Run("requester-client", func(t *testing.T) {
		resp := decodeTokenResponse(t, postToken(t, cfg, kp, store, clientCredentials("requester-client", "secret", "optional-scope2")))
		if resp.Scope != "default-scope1 optional-scope2" {
			t.Errorf("scope = %q", resp.Scope)
		}
		claims := parseClaims(t, kp, resp.AccessToken)
		if claims["aud"] != "requester-client" {
			t.Errorf("aud = %#v, want the single string \"requester-client\"", claims["aud"])
		}
		if claims["azp"] != "requester-client" || claims["typ"] != "Bearer" {
			t.Errorf("azp = %v, typ = %v", claims["azp"], claims["typ"])
		}
		if resp.RefreshToken != "" {
			t.Error("client_credentials must not return a refresh token")
		}
	})

	t.Run("scope not assigned to the client", func(t *testing.T) {
		// optional-scope3 exists in the realm but is not assigned to requester-client.
		assertTokenError(t, postToken(t, cfg, kp, store, clientCredentials("requester-client", "secret", "optional-scope3")), "invalid_scope")
		// requester-client-2 does not have profile among its scopes.
		assertTokenError(t, postToken(t, cfg, kp, store, clientCredentials("requester-client-2", "secret", "profile")), "invalid_scope")
	})

	t.Run("subject-client has two audiences", func(t *testing.T) {
		resp := decodeTokenResponse(t, postToken(t, cfg, kp, store, clientCredentials("subject-client", "secret", "")))
		if got := audience(t, parseClaims(t, kp, resp.AccessToken)); !reflect.DeepEqual(got, []string{"subject-client", "requester-client"}) {
			t.Errorf("aud = %v", got)
		}
	})
}
