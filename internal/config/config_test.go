package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()

	t.Run("valid config", func(t *testing.T) {
		path := filepath.Join(dir, "valid.json")
		os.WriteFile(path, []byte(`{
			"realm": "test",
			"enabled": true,
			"accessTokenLifespan": 600,
			"refreshTokenMaxReuse": 3600,
			"accessCodeLifespan": 120,
			"defaultSignatureAlgorithm": "ES256",
			"clients": [],
			"users": []
		}`), 0644)

		cfg, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Realm.Realm != "test" {
			t.Errorf("got realm %q, want %q", cfg.Realm.Realm, "test")
		}
		if cfg.Realm.AccessTokenLifespan != 600 {
			t.Errorf("got lifespan %d, want 600", cfg.Realm.AccessTokenLifespan)
		}
		if cfg.Realm.RefreshTokenLifespan != 3600 {
			t.Errorf("got refresh lifespan %d, want 3600", cfg.Realm.RefreshTokenLifespan)
		}
		if cfg.Realm.AccessCodeLifespan != 120 {
			t.Errorf("got code lifespan %d, want 120", cfg.Realm.AccessCodeLifespan)
		}
		if cfg.Realm.SigningAlgorithm != "ES256" {
			t.Errorf("got alg %q, want ES256", cfg.Realm.SigningAlgorithm)
		}
	})

	t.Run("defaults applied", func(t *testing.T) {
		path := filepath.Join(dir, "defaults.json")
		os.WriteFile(path, []byte(`{"realm": "minimal"}`), 0644)

		cfg, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Realm.AccessTokenLifespan != 300 {
			t.Errorf("default access token lifespan: got %d, want 300", cfg.Realm.AccessTokenLifespan)
		}
		if cfg.Realm.RefreshTokenLifespan != 1800 {
			t.Errorf("default refresh lifespan: got %d, want 1800", cfg.Realm.RefreshTokenLifespan)
		}
		if cfg.Realm.AccessCodeLifespan != 60 {
			t.Errorf("default code lifespan: got %d, want 60", cfg.Realm.AccessCodeLifespan)
		}
		if cfg.Realm.SigningAlgorithm != "RS256" {
			t.Errorf("default algorithm: got %q, want RS256", cfg.Realm.SigningAlgorithm)
		}
	})

	t.Run("missing realm name", func(t *testing.T) {
		path := filepath.Join(dir, "norealm.json")
		os.WriteFile(path, []byte(`{"enabled": true}`), 0644)

		_, err := Load(path)
		if err == nil {
			t.Fatal("expected error for missing realm name")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		path := filepath.Join(dir, "bad.json")
		os.WriteFile(path, []byte(`{not json`), 0644)

		_, err := Load(path)
		if err == nil {
			t.Fatal("expected error for invalid json")
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := Load(filepath.Join(dir, "nonexistent.json"))
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})
}

func TestGetAlgorithm(t *testing.T) {
	tests := []struct {
		alg  string
		want string
	}{
		{"RS256", "RS256"},
		{"ES256", "ES256"},
		{"EdDSA", "EdDSA"},
		{"unknown", "RS256"},
		{"", "RS256"},
	}
	for _, tt := range tests {
		cfg := &Config{Realm: RealmConfig{SigningAlgorithm: tt.alg}}
		got := string(cfg.GetAlgorithm())
		if got != tt.want {
			t.Errorf("GetAlgorithm(%q) = %q, want %q", tt.alg, got, tt.want)
		}
	}
}

func TestFindClient(t *testing.T) {
	cfg := &Config{Realm: RealmConfig{
		Clients: []ClientConfig{
			{ClientID: "client-a", Name: "A"},
			{ClientID: "client-b", Name: "B"},
		},
	}}

	c := cfg.FindClient("client-a")
	if c == nil || c.Name != "A" {
		t.Error("expected to find client-a")
	}

	c = cfg.FindClient("missing")
	if c != nil {
		t.Error("expected nil for missing client")
	}
}

func TestFindUser(t *testing.T) {
	cfg := &Config{Realm: RealmConfig{
		Users: []UserConfig{
			{Username: "alice", Email: "alice@example.com"},
			{Username: "bob", Email: "bob@example.com"},
		},
	}}

	u := cfg.FindUser("bob")
	if u == nil || u.Email != "bob@example.com" {
		t.Error("expected to find bob")
	}

	u = cfg.FindUser("missing")
	if u != nil {
		t.Error("expected nil for missing user")
	}
}

func TestValidateUserPassword(t *testing.T) {
	cfg := &Config{Realm: RealmConfig{
		Users: []UserConfig{
			{
				Username: "user1",
				Enabled:  true,
				Credentials: []CredentialConfig{
					{Type: "password", Value: "secret"},
				},
			},
			{
				Username: "disabled",
				Enabled:  false,
				Credentials: []CredentialConfig{
					{Type: "password", Value: "pass"},
				},
			},
		},
	}}

	if cfg.ValidateUserPassword("user1", "secret") == nil {
		t.Error("expected successful validation")
	}
	if cfg.ValidateUserPassword("user1", "wrong") != nil {
		t.Error("expected nil for wrong password")
	}
	if cfg.ValidateUserPassword("disabled", "pass") != nil {
		t.Error("expected nil for disabled user")
	}
	if cfg.ValidateUserPassword("nobody", "x") != nil {
		t.Error("expected nil for nonexistent user")
	}
}

func TestResolveMappers(t *testing.T) {
	client := &ClientConfig{
		ProtocolMappers: []ProtocolMapperConfig{
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
			{
				Name:           "department",
				Protocol:       "openid-connect",
				ProtocolMapper: "oidc-usermodel-attribute-mapper",
				Config: map[string]string{
					"user.attribute":       "department",
					"claim.name":           "dept",
					"id.token.claim":       "true",
					"access.token.claim":   "false",
					"userinfo.token.claim": "true",
				},
			},
			{
				Name:           "groups",
				Protocol:       "openid-connect",
				ProtocolMapper: "oidc-usermodel-attribute-mapper",
				Config: map[string]string{
					"user.attribute":       "groups",
					"claim.name":           "groups",
					"id.token.claim":       "true",
					"access.token.claim":   "true",
					"userinfo.token.claim": "true",
					"multivalued":          "true",
				},
			},
			{
				Name:           "other-mapper-type",
				Protocol:       "openid-connect",
				ProtocolMapper: "oidc-role-mapper",
				Config: map[string]string{
					"claim.name":     "roles",
					"id.token.claim": "true",
				},
			},
		},
	}

	user := &UserConfig{
		Attributes: map[string][]string{
			"birthdate":  {"1990-01-15"},
			"department": {"engineering"},
			"groups":     {"admin", "users"},
		},
	}

	t.Run("id.token claims", func(t *testing.T) {
		extra := client.ResolveMappers(user, "id.token")
		if extra == nil {
			t.Fatal("expected extra claims")
		}
		if extra["birthdate"] != "1990-01-15" {
			t.Errorf("birthdate = %v", extra["birthdate"])
		}
		if extra["dept"] != "engineering" {
			t.Errorf("dept = %v", extra["dept"])
		}
		groups, ok := extra["groups"].([]string)
		if !ok || len(groups) != 2 {
			t.Errorf("groups = %v", extra["groups"])
		}
	})

	t.Run("access.token claims", func(t *testing.T) {
		extra := client.ResolveMappers(user, "access.token")
		if extra == nil {
			t.Fatal("expected extra claims")
		}
		if extra["birthdate"] != "1990-01-15" {
			t.Errorf("birthdate = %v", extra["birthdate"])
		}
		if _, ok := extra["dept"]; ok {
			t.Error("dept should not be in access token")
		}
	})

	t.Run("userinfo.token claims", func(t *testing.T) {
		extra := client.ResolveMappers(user, "userinfo.token")
		if extra == nil {
			t.Fatal("expected extra claims")
		}
		if extra["birthdate"] != "1990-01-15" {
			t.Errorf("birthdate = %v", extra["birthdate"])
		}
		if extra["dept"] != "engineering" {
			t.Errorf("dept = %v", extra["dept"])
		}
	})

	t.Run("nil client", func(t *testing.T) {
		var nilClient *ClientConfig
		if nilClient.ResolveMappers(user, "id.token") != nil {
			t.Error("expected nil for nil client")
		}
	})

	t.Run("nil user", func(t *testing.T) {
		if client.ResolveMappers(nil, "id.token") != nil {
			t.Error("expected nil for nil user")
		}
	})

	t.Run("nil attributes", func(t *testing.T) {
		u := &UserConfig{Attributes: nil}
		if client.ResolveMappers(u, "id.token") != nil {
			t.Error("expected nil for nil attributes")
		}
	})

	t.Run("attribute not present", func(t *testing.T) {
		u := &UserConfig{Attributes: map[string][]string{"other": {"val"}}}
		extra := client.ResolveMappers(u, "id.token")
		if extra != nil {
			t.Errorf("expected nil, got %v", extra)
		}
	})

	t.Run("empty attribute value", func(t *testing.T) {
		u := &UserConfig{Attributes: map[string][]string{"birthdate": {}}}
		extra := client.ResolveMappers(u, "id.token")
		if extra != nil {
			t.Errorf("expected nil for empty values, got %v", extra)
		}
	})

	t.Run("missing claim.name config", func(t *testing.T) {
		c := &ClientConfig{
			ProtocolMappers: []ProtocolMapperConfig{{
				ProtocolMapper: "oidc-usermodel-attribute-mapper",
				Config: map[string]string{
					"user.attribute": "birthdate",
					"id.token.claim": "true",
				},
			}},
		}
		u := &UserConfig{Attributes: map[string][]string{"birthdate": {"1990-01-01"}}}
		if c.ResolveMappers(u, "id.token") != nil {
			t.Error("expected nil when claim.name missing")
		}
	})
}
