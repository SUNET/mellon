package config

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestGrantScopes uses Keycloak's token-exchange test realm, which defines
// its own clientScopes and assigns different default/optional sets per client.
func TestGrantScopes(t *testing.T) {
	cfg := loadTestdata(t, "token-exchange-v2.json")

	rcDefaults := []string{"service_account", "acr", "default-scope1", "roles", "basic"}
	tests := []struct {
		client    string
		requested string
		want      []string
		invalid   []string
	}{
		{"requester-client", "", rcDefaults, nil},
		{"requester-client", "openid", append([]string{"openid"}, rcDefaults...), nil},
		{"requester-client", "default-scope1", rcDefaults, nil},
		{"requester-client", "optional-scope2 profile", append([]string{"optional-scope2", "profile"}, rcDefaults...), nil},
		{"requester-client", "optional-scope2 optional-scope2", append([]string{"optional-scope2"}, rcDefaults...), nil},
		{"requester-client", "optional-scope3", nil, []string{"optional-scope3"}},
		{"requester-client", "admin optional-scope2 bogus", nil, []string{"admin", "bogus"}},
		{"requester-client-2", "profile", nil, []string{"profile"}},
		{"requester-client-public", "", []string{"acr", "roles", "basic"}, nil},
		{"requester-client-public", "offline_access", nil, []string{"offline_access"}},
		{"subject-client", "openid optional-requester-scope", []string{"openid", "service_account", "acr", "roles", "profile", "basic", "email", "optional-requester-scope"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.client+"/"+tt.requested, func(t *testing.T) {
			got, err := cfg.GrantScopes(cfg.FindClient(tt.client), tt.requested)
			if tt.invalid != nil {
				var se *ScopeError
				if !errors.As(err, &se) || !errors.Is(err, ErrInvalidScope) {
					t.Fatalf("err = %v, want ScopeError", err)
				}
				if !reflect.DeepEqual(se.Invalid, tt.invalid) {
					t.Errorf("invalid = %v, want %v", se.Invalid, tt.invalid)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !sameScopes(got, tt.want) {
				t.Errorf("granted = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEffectiveScopes_Fallbacks(t *testing.T) {
	t.Run("built-ins when nothing configured", func(t *testing.T) {
		cfg := &Config{}
		c := &ClientConfig{ClientID: "c"}
		if got := cfg.EffectiveDefaultScopes(c); !reflect.DeepEqual(got, builtinDefaultScopes) {
			t.Errorf("defaults = %v", got)
		}
		if got := cfg.EffectiveOptionalScopes(c); !reflect.DeepEqual(got, builtinOptionalScopes) {
			t.Errorf("optional = %v", got)
		}
	})

	t.Run("realm lists when client omits", func(t *testing.T) {
		cfg := &Config{Realm: RealmConfig{
			DefaultDefaultClientScopes:  []string{"email"},
			DefaultOptionalClientScopes: []string{"phone"},
		}}
		c := &ClientConfig{ClientID: "c"}
		if got := cfg.EffectiveDefaultScopes(c); !reflect.DeepEqual(got, []string{"email"}) {
			t.Errorf("defaults = %v", got)
		}
		if got := cfg.EffectiveOptionalScopes(c); !reflect.DeepEqual(got, []string{"phone"}) {
			t.Errorf("optional = %v", got)
		}
	})

	t.Run("explicit empty list means none", func(t *testing.T) {
		cfg := &Config{}
		c := &ClientConfig{ClientID: "c", DefaultClientScopes: []string{}, OptionalClientScopes: []string{}}
		if got := cfg.EffectiveDefaultScopes(c); len(got) != 0 {
			t.Errorf("defaults = %v", got)
		}
		if got := cfg.EffectiveOptionalScopes(c); len(got) != 0 {
			t.Errorf("optional = %v", got)
		}
		if _, err := cfg.GrantScopes(c, "profile"); !errors.Is(err, ErrInvalidScope) {
			t.Errorf("err = %v, want invalid scope", err)
		}
		got, err := cfg.GrantScopes(c, "openid")
		if err != nil || !reflect.DeepEqual(got, []string{"openid"}) {
			t.Errorf("granted = %v, err = %v", got, err)
		}
	})

	t.Run("undefined and openid entries dropped", func(t *testing.T) {
		cfg := loadTestdata(t, "token-exchange-v2.json")
		c := &ClientConfig{DefaultClientScopes: []string{"openid", "nope", "default-scope1", "default-scope1", "role_list"}}
		if got := cfg.EffectiveDefaultScopes(c); !reflect.DeepEqual(got, []string{"default-scope1"}) {
			t.Errorf("defaults = %v", got)
		}
	})

	t.Run("optional overlapping default dropped", func(t *testing.T) {
		cfg := &Config{}
		c := &ClientConfig{DefaultClientScopes: []string{"email"}, OptionalClientScopes: []string{"email", "phone"}}
		if got := cfg.EffectiveOptionalScopes(c); !reflect.DeepEqual(got, []string{"phone"}) {
			t.Errorf("optional = %v", got)
		}
	})
}

func TestTokenScope(t *testing.T) {
	cfg := &Config{}
	got := cfg.TokenScope([]string{"openid", "profile", "email", "roles", "web-origins", "acr", "basic", "offline_access"})
	if got != "openid profile email offline_access" {
		t.Errorf("TokenScope = %q", got)
	}

	cfg = &Config{Realm: RealmConfig{ClientScopes: []ClientScopeConfig{
		{Name: "a"},
		{Name: "hidden", Attributes: map[string]string{AttrIncludeInTokenScope: "false"}},
	}}}
	if got := cfg.TokenScope([]string{"a", "hidden"}); got != "a" {
		t.Errorf("TokenScope = %q", got)
	}
}

func TestHasScope(t *testing.T) {
	if !HasScope("openid profile", "profile") {
		t.Error("expected profile")
	}
	if HasScope("openidx profiles", "openid") || HasScope("openidx profiles", "profile") {
		t.Error("HasScope must match whole entries")
	}
}

func TestAudiences(t *testing.T) {
	cfg := &Config{Realm: RealmConfig{ClientScopes: []ClientScopeConfig{
		{Name: "api", ProtocolMappers: []ProtocolMapperConfig{{
			ProtocolMapper: "oidc-audience-mapper",
			Config:         map[string]string{"included.client.audience": "api-backend", "access.token.claim": "true"},
		}}},
		{Name: "other"},
	}}}
	client := &ClientConfig{ClientID: "c", ProtocolMappers: []ProtocolMapperConfig{
		{ProtocolMapper: "oidc-audience-mapper", Config: map[string]string{
			"included.custom.audience": "custom", "access.token.claim": "true", "id.token.claim": "true",
		}},
		{ProtocolMapper: "oidc-audience-mapper", Config: map[string]string{
			"included.client.audience": "wins", "included.custom.audience": "loses", "access.token.claim": "true",
		}},
		{ProtocolMapper: "oidc-audience-mapper", Config: map[string]string{
			"included.custom.audience": "custom", "access.token.claim": "true",
		}},
		{ProtocolMapper: "oidc-audience-mapper", Config: map[string]string{
			"included.custom.audience": "off", "access.token.claim": "false",
		}},
		{ProtocolMapper: "oidc-audience-mapper", Protocol: "saml", Config: map[string]string{
			"included.custom.audience": "saml-only", "access.token.claim": "true",
		}},
		{ProtocolMapper: "oidc-usermodel-attribute-mapper", Config: map[string]string{
			"included.custom.audience": "ignored", "access.token.claim": "true",
		}},
	}}

	if got := cfg.Audiences(client, nil, "access.token"); !reflect.DeepEqual(got, []string{"custom", "wins"}) {
		t.Errorf("access aud = %v", got)
	}
	if got := cfg.Audiences(client, []string{"api"}, "access.token"); !reflect.DeepEqual(got, []string{"custom", "wins", "api-backend"}) {
		t.Errorf("access aud with scope = %v", got)
	}
	if got := cfg.Audiences(client, []string{"api"}, "id.token"); !reflect.DeepEqual(got, []string{"custom"}) {
		t.Errorf("id aud = %v", got)
	}
	if got := cfg.Audiences(nil, nil, "access.token"); got != nil {
		t.Errorf("nil client aud = %v", got)
	}
}

func TestResolveClaims_ScopeMappers(t *testing.T) {
	cfg := &Config{Realm: RealmConfig{ClientScopes: []ClientScopeConfig{
		{Name: "birth", ProtocolMappers: []ProtocolMapperConfig{{
			ProtocolMapper: "oidc-usermodel-attribute-mapper",
			Config: map[string]string{
				"user.attribute": "birthdate", "claim.name": "birthdate", "access.token.claim": "true",
			},
		}}},
	}}}
	client := &ClientConfig{ClientID: "c"}
	user := &UserConfig{Attributes: map[string][]string{"birthdate": {"2000-01-01"}}}

	if got := cfg.ResolveClaims(client, nil, user, "access.token"); got != nil {
		t.Errorf("without scope = %v", got)
	}
	got := cfg.ResolveClaims(client, []string{"birth"}, user, "access.token")
	if got["birthdate"] != "2000-01-01" {
		t.Errorf("with scope = %v", got)
	}
}

func TestSupportedScopes(t *testing.T) {
	got := (&Config{}).SupportedScopes()
	want := []string{"openid", "profile", "email", "offline_access", "phone", "address", "microprofile-jwt"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("built-in = %v", got)
	}
	// Only OIDC scopes that are included in the token scope are advertised.
	got = loadTestdata(t, "conformance-oidc.json").SupportedScopes()
	want = []string{"openid", "name_claims", "consents", "address", "phone", "microprofile-jwt", "consent:1", "profile", "offline_access", "resources", "email", "name_claims_for_implicit"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("conformance-oidc = %v", got)
	}
}

func TestLoad_UndefinedScopeWarning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "realm.json")
	os.WriteFile(path, []byte(`{
		"realm": "r",
		"clientScopes": [{"name": "a", "protocol": "openid-connect"}],
		"clients": [{"clientId": "c", "defaultClientScopes": ["openid", "a", "missing"]}]
	}`), 0o644)

	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	}()

	cfg, err := Load(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	logs := buf.String()
	if !strings.Contains(logs, `client "c" defaultClientScopes references undefined client scope "missing"`) {
		t.Errorf("missing warning in %q", logs)
	}
	if strings.Contains(logs, `"openid"`) || strings.Contains(logs, `scope "a"`) {
		t.Errorf("unexpected warning: %q", logs)
	}
	if got := cfg.EffectiveDefaultScopes(cfg.FindClient("c")); !reflect.DeepEqual(got, []string{"a"}) {
		t.Errorf("defaults = %v", got)
	}
}
