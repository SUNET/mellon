package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"

	opcrypto "github.com/masv3971/mellon/internal/crypto"
)

type Config struct {
	Realm  RealmConfig
	Issuer string
}

type RealmConfig struct {
	Realm                string         `json:"realm"`
	Enabled              bool           `json:"enabled"`
	SSLRequired          string         `json:"sslRequired"`
	AccessTokenLifespan  int            `json:"accessTokenLifespan"`
	RefreshTokenLifespan int            `json:"refreshTokenMaxReuse"`
	AccessCodeLifespan   int            `json:"accessCodeLifespan"`
	PrivateKey           string         `json:"privateKey"`
	Certificate          string         `json:"certificate"`
	SigningAlgorithm     string         `json:"defaultSignatureAlgorithm"`
	Clients              []ClientConfig `json:"clients"`
	Users                []UserConfig   `json:"users"`
	Roles                *RolesConfig   `json:"roles"`

	// ClientScopes defines the realm's client scopes. When the key is
	// absent (nil) the Keycloak built-in scopes are used; when present,
	// only the listed scopes exist (Keycloak import semantics).
	ClientScopes []ClientScopeConfig `json:"clientScopes"`
	// DefaultDefaultClientScopes / DefaultOptionalClientScopes are the
	// realm-level scope lists used for clients that omit their own lists.
	DefaultDefaultClientScopes  []string `json:"defaultDefaultClientScopes"`
	DefaultOptionalClientScopes []string `json:"defaultOptionalClientScopes"`
}

// ClientScopeConfig mirrors a Keycloak client scope representation.
type ClientScopeConfig struct {
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Protocol        string                 `json:"protocol"`
	Attributes      map[string]string      `json:"attributes"`
	ProtocolMappers []ProtocolMapperConfig `json:"protocolMappers"`
}

type ClientConfig struct {
	ClientID                  string                 `json:"clientId"`
	Name                      string                 `json:"name"`
	Secret                    string                 `json:"secret"`
	RedirectURIs              []string               `json:"redirectUris"`
	WebOrigins                []string               `json:"webOrigins"`
	PublicClient              bool                   `json:"publicClient"`
	StandardFlowEnabled       bool                   `json:"standardFlowEnabled"`
	ImplicitFlowEnabled       bool                   `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled bool                   `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled    bool                   `json:"serviceAccountsEnabled"`
	DefaultClientScopes       []string               `json:"defaultClientScopes"`
	OptionalClientScopes      []string               `json:"optionalClientScopes"`
	ProtocolMappers           []ProtocolMapperConfig `json:"protocolMappers"`
}

type ProtocolMapperConfig struct {
	Name            string            `json:"name"`
	Protocol        string            `json:"protocol"`
	ProtocolMapper  string            `json:"protocolMapper"`
	ConsentRequired bool              `json:"consentRequired"`
	Config          map[string]string `json:"config"`
}

type UserConfig struct {
	Username      string              `json:"username"`
	Email         string              `json:"email"`
	EmailVerified bool                `json:"emailVerified"`
	FirstName     string              `json:"firstName"`
	LastName      string              `json:"lastName"`
	Enabled       bool                `json:"enabled"`
	Credentials   []CredentialConfig  `json:"credentials"`
	ClientRoles   map[string][]string `json:"clientRoles"`
	RealmRoles    []string            `json:"realmRoles"`
	Attributes    AttributeMap        `json:"attributes"`
}

// AttributeMap holds multi-valued user attributes. Like Keycloak's
// StringListMapDeserializer, each value may be a scalar or an array of
// scalars; scalars (strings, numbers, booleans) are kept as their text:
// {"a": "x", "b": ["y", "z"], "verified": true, "updatedAt": 1582521468}.
type AttributeMap map[string][]string

func (m *AttributeMap) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == nil {
		*m = nil
		return nil
	}
	out := make(AttributeMap, len(raw))
	for k, v := range raw {
		var list []json.RawMessage
		if err := json.Unmarshal(v, &list); err != nil {
			list = []json.RawMessage{v}
		}
		values := make([]string, 0, len(list))
		for _, item := range list {
			s, err := attributeText(item)
			if err != nil {
				return fmt.Errorf("attribute %q: %w", k, err)
			}
			values = append(values, s)
		}
		out[k] = values
	}
	*m = out
	return nil
}

// attributeText returns the text of a JSON scalar (string, number, bool).
func attributeText(v json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		return s, nil
	}
	var scalar any
	if err := json.Unmarshal(v, &scalar); err != nil {
		return "", err
	}
	switch scalar.(type) {
	case float64, bool:
		return string(bytes.TrimSpace(v)), nil
	default:
		return "", fmt.Errorf("want a string, number, boolean or array of them")
	}
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

	realm, err := parseRealm(data)
	if err != nil {
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

	cfg := &Config{Realm: realm}
	cfg.warnUndefinedScopes()
	return cfg, nil
}

// parseRealm decodes a realm representation. Keycloak also accepts a JSON
// array of realms in one import file; mellon serves a single realm, so it
// picks the first one that is not "master" (or "master" if that is all
// there is) and logs the choice.
func parseRealm(data []byte) (RealmConfig, error) {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '[' {
		var realm RealmConfig
		err := json.Unmarshal(data, &realm)
		return realm, err
	}

	var realms []RealmConfig
	if err := json.Unmarshal(data, &realms); err != nil {
		return RealmConfig{}, err
	}
	if len(realms) == 0 {
		return RealmConfig{}, fmt.Errorf("realm array is empty")
	}
	chosen := 0
	for i, r := range realms {
		if r.Realm != "master" {
			chosen = i
			break
		}
	}
	if len(realms) > 1 {
		names := make([]string, len(realms))
		for i, r := range realms {
			names[i] = r.Realm
		}
		log.Printf("config: file contains %d realms %v; serving %q", len(realms), names, realms[chosen].Realm)
	}
	return realms[chosen], nil
}

// warnUndefinedScopes logs references to client scopes that are not
// defined in the realm. Like Keycloak, such references are ignored.
func (c *Config) warnUndefinedScopes() {
	check := func(owner string, names []string) {
		for _, n := range names {
			if n == "openid" {
				continue
			}
			if !c.clientScopeDefined(n) {
				log.Printf("WARNING: config: %s references undefined client scope %q; ignoring", owner, n)
			}
		}
	}
	check("realm defaultDefaultClientScopes", c.Realm.DefaultDefaultClientScopes)
	check("realm defaultOptionalClientScopes", c.Realm.DefaultOptionalClientScopes)
	for _, cl := range c.Realm.Clients {
		check(fmt.Sprintf("client %q defaultClientScopes", cl.ClientID), cl.DefaultClientScopes)
		check(fmt.Sprintf("client %q optionalClientScopes", cl.ClientID), cl.OptionalClientScopes)
	}
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

// AllowedOrigins returns the CORS origins permitted for this client, derived
// from webOrigins using Keycloak semantics: exact origins are kept, "+"
// expands to the origins of all absolute redirectUris, and "*" allows any
// origin. The result is deduplicated; nil if no origins are allowed.
func (c *ClientConfig) AllowedOrigins() []string {
	if c == nil {
		return nil
	}
	var out []string
	seen := make(map[string]bool)
	add := func(o string) {
		if o == "" || seen[o] {
			return
		}
		seen[o] = true
		out = append(out, o)
	}
	for _, wo := range c.WebOrigins {
		wo = strings.TrimSpace(wo)
		switch wo {
		case "+":
			for _, ru := range c.RedirectURIs {
				add(originOf(ru))
			}
		default:
			add(strings.TrimSuffix(wo, "/"))
		}
	}
	return out
}

// originOf returns scheme://host[:port] of an absolute URI, or "" if the
// URI is relative or unparsable. A trailing "*" wildcard is tolerated.
// The result is normalized the way browsers serialize the Origin header:
// scheme and host are lowercased and default ports (80 for http, 443 for
// https) are omitted.
func originOf(uri string) string {
	uri = strings.TrimSuffix(strings.TrimSpace(uri), "*")
	u, err := url.Parse(uri)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host
}

// ResolveMappers returns extra claims for the given token target based on
// the client's protocol mappers and the user's attributes.
func (c *ClientConfig) ResolveMappers(user *UserConfig, target string) map[string]any {
	if c == nil {
		return nil
	}
	return resolveAttributeMappers(c.ProtocolMappers, user, target)
}

// resolveAttributeMappers evaluates oidc-usermodel-attribute-mapper entries
// for the given token target ("id.token", "access.token", "userinfo.token").
func resolveAttributeMappers(mappers []ProtocolMapperConfig, user *UserConfig, target string) map[string]any {
	if user == nil || user.Attributes == nil {
		return nil
	}

	extra := make(map[string]any)

	for _, m := range mappers {
		if m.ProtocolMapper != "oidc-usermodel-attribute-mapper" {
			continue
		}
		if !mapperIncludedIn(m, target) {
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
