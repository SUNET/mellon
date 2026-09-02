package config

import (
	"encoding/json"
	"fmt"
	"os"

	opcrypto "github.com/masv3971/mellon/internal/crypto"
)

type Config struct {
	Realm  RealmConfig
	Issuer string
}

type RealmConfig struct {
	Realm                  string         `json:"realm"`
	Enabled                bool           `json:"enabled"`
	SSLRequired            string         `json:"sslRequired"`
	AccessTokenLifespan    int            `json:"accessTokenLifespan"`
	RefreshTokenLifespan   int            `json:"refreshTokenMaxReuse"`
	AccessCodeLifespan     int            `json:"accessCodeLifespan"`
	PrivateKey             string         `json:"privateKey"`
	Certificate            string         `json:"certificate"`
	SigningAlgorithm       string         `json:"defaultSignatureAlgorithm"`
	Clients                []ClientConfig `json:"clients"`
	Users                  []UserConfig   `json:"users"`
	Roles                  *RolesConfig   `json:"roles"`
}

type ClientConfig struct {
	ClientID                   string                 `json:"clientId"`
	Name                       string                 `json:"name"`
	Secret                     string                 `json:"secret"`
	RedirectURIs               []string               `json:"redirectUris"`
	WebOrigins                 []string               `json:"webOrigins"`
	PublicClient               bool                   `json:"publicClient"`
	StandardFlowEnabled        bool                   `json:"standardFlowEnabled"`
	ImplicitFlowEnabled        bool                   `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled  bool                   `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled     bool                   `json:"serviceAccountsEnabled"`
	DefaultClientScopes        []string               `json:"defaultClientScopes"`
	OptionalClientScopes       []string               `json:"optionalClientScopes"`
	ProtocolMappers            []ProtocolMapperConfig `json:"protocolMappers"`
}

type ProtocolMapperConfig struct {
	Name            string            `json:"name"`
	Protocol        string            `json:"protocol"`
	ProtocolMapper  string            `json:"protocolMapper"`
	ConsentRequired bool              `json:"consentRequired"`
	Config          map[string]string `json:"config"`
}

type UserConfig struct {
	Username      string                  `json:"username"`
	Email         string                  `json:"email"`
	EmailVerified bool                    `json:"emailVerified"`
	FirstName     string                  `json:"firstName"`
	LastName      string                  `json:"lastName"`
	Enabled       bool                    `json:"enabled"`
	Credentials   []CredentialConfig      `json:"credentials"`
	ClientRoles   map[string][]string     `json:"clientRoles"`
	RealmRoles    []string                `json:"realmRoles"`
	Attributes    map[string][]string     `json:"attributes"`
}

type CredentialConfig struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type RolesConfig struct {
	Realm  []RoleConfig            `json:"realm"`
	Client map[string][]RoleConfig `json:"client"`
}

type RoleConfig struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Load reads a Keycloak-style realm.json from disk and expands
// ${env.NAME} / ${sys.NAME} placeholders (with optional ":default")
// before parsing. sysProps supplies values for ${sys.*}; pass nil if none.
func Load(path string, sysProps map[string]string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	data, err = expandProperties(data, sysProps)
	if err != nil {
		return nil, fmt.Errorf("expand config properties: %w", err)
	}

	var realm RealmConfig
	if err := json.Unmarshal(data, &realm); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if realm.Realm == "" {
		return nil, fmt.Errorf("realm name is required")
	}
	if realm.AccessTokenLifespan == 0 {
		realm.AccessTokenLifespan = 300
	}
	if realm.RefreshTokenLifespan == 0 {
		realm.RefreshTokenLifespan = 1800
	}
	if realm.AccessCodeLifespan == 0 {
		realm.AccessCodeLifespan = 60
	}
	if realm.SigningAlgorithm == "" {
		realm.SigningAlgorithm = "RS256"
	}

	return &Config{Realm: realm}, nil
}

func (c *Config) GetAlgorithm() opcrypto.Algorithm {
	switch c.Realm.SigningAlgorithm {
	case "ES256":
		return opcrypto.ES256
	case "EdDSA":
		return opcrypto.EdDSA
	default:
		return opcrypto.RS256
	}
}

func (c *Config) FindClient(clientID string) *ClientConfig {
	for i := range c.Realm.Clients {
		if c.Realm.Clients[i].ClientID == clientID {
			return &c.Realm.Clients[i]
		}
	}
	return nil
}

func (c *Config) FindUser(username string) *UserConfig {
	for i := range c.Realm.Users {
		if c.Realm.Users[i].Username == username {
			return &c.Realm.Users[i]
		}
	}
	return nil
}

func (c *Config) ValidateUserPassword(username, password string) *UserConfig {
	user := c.FindUser(username)
	if user == nil || !user.Enabled {
		return nil
	}
	for _, cred := range user.Credentials {
		if cred.Type == "password" && cred.Value == password {
			return user
		}
	}
	return nil
}

// ResolveMappers returns extra claims for the given token target based on
// the client's protocol mappers and the user's attributes.
func (c *ClientConfig) ResolveMappers(user *UserConfig, target string) map[string]any {
	if c == nil || user == nil || user.Attributes == nil {
		return nil
	}

	targetKey := target + ".claim"
	extra := make(map[string]any)

	for _, m := range c.ProtocolMappers {
		if m.ProtocolMapper != "oidc-usermodel-attribute-mapper" {
			continue
		}
		if m.Config[targetKey] != "true" {
			continue
		}
		attrName := m.Config["user.attribute"]
		claimName := m.Config["claim.name"]
		if attrName == "" || claimName == "" {
			continue
		}
		values, ok := user.Attributes[attrName]
		if !ok || len(values) == 0 {
			continue
		}
		if m.Config["multivalued"] == "true" {
			extra[claimName] = values
		} else {
			extra[claimName] = values[0]
		}
	}

	if len(extra) == 0 {
		return nil
	}
	return extra
}
