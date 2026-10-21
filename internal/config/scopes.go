package config

import (
	"errors"
	"strings"
)

// ErrInvalidScope is returned (wrapped in *ScopeError) when a client
// requests a scope that is neither one of its default nor optional client
// scopes.
var ErrInvalidScope = errors.New("invalid_scope")

// ScopeError lists the requested scopes that were rejected. Its message
// matches Keycloak's error_description ("Invalid scopes: ...").
type ScopeError struct {
	Invalid []string
}

func (e *ScopeError) Error() string {
	return "Invalid scopes: " + strings.Join(e.Invalid, " ")
}

func (e *ScopeError) Unwrap() error { return ErrInvalidScope }

const (
	// ScopeOpenID is the OIDC marker scope. Like Keycloak, it is not a
	// client scope: it is granted only when requested and never needs to
	// be listed on the client.
	ScopeOpenID = "openid"

	// AttrIncludeInTokenScope controls whether a client scope's name is
	// placed in the token "scope" claim. Absent means true (Keycloak).
	AttrIncludeInTokenScope = "include.in.token.scope"

	protocolOIDC = "openid-connect"
)

// Keycloak's built-in realm default/optional client scopes.
var (
	builtinDefaultScopes  = []string{"profile", "email", "roles", "web-origins", "acr", "basic"}
	builtinOptionalScopes = []string{"offline_access", "phone", "address", "microprofile-jwt"}
)

// builtinClientScopes returns the client scopes Keycloak creates for a realm
// imported without a "clientScopes" key.
func builtinClientScopes() []ClientScopeConfig {
	hidden := map[string]string{AttrIncludeInTokenScope: "false"}
	shown := map[string]string{AttrIncludeInTokenScope: "true"}
	mk := func(name string, attrs map[string]string) ClientScopeConfig {
		return ClientScopeConfig{Name: name, Protocol: protocolOIDC, Attributes: attrs}
	}
	return []ClientScopeConfig{
		mk("profile", shown),
		mk("email", shown),
		mk("offline_access", shown),
		mk("phone", shown),
		mk("address", shown),
		mk("microprofile-jwt", shown),
		mk("roles", hidden),
		mk("web-origins", hidden),
		mk("acr", hidden),
		mk("basic", hidden),
	}
}

// clientScopes returns the realm's defined client scopes, falling back to
// the Keycloak built-ins when the realm does not define any.
func (c *Config) clientScopes() []ClientScopeConfig {
	if c.Realm.ClientScopes == nil {
		return builtinClientScopes()
	}
	return c.Realm.ClientScopes
}

// FindClientScope returns the OIDC client scope with the given name, or nil.
func (c *Config) FindClientScope(name string) *ClientScopeConfig {
	scopes := c.clientScopes()
	for i := range scopes {
		s := &scopes[i]
		if s.Name == name && (s.Protocol == "" || s.Protocol == protocolOIDC) {
			return s
		}
	}
	return nil
}

// clientScopeDefined reports whether a client scope with this name exists
// for any protocol. Non-OIDC scopes (e.g. SAML "role_list") are valid
// references that simply do not apply to OIDC tokens.
func (c *Config) clientScopeDefined(name string) bool {
	for _, s := range c.clientScopes() {
		if s.Name == name {
			return true
		}
	}
	return false
}

// IncludeInTokenScope reports whether the scope name appears in the token
// "scope" claim (Keycloak: attribute absent means true).
func (s *ClientScopeConfig) IncludeInTokenScope() bool {
	if s == nil {
		return false
	}
	v, ok := s.Attributes[AttrIncludeInTokenScope]
	return !ok || !strings.EqualFold(v, "false")
}

// EffectiveDefaultScopes returns the client's default client scopes. A client
// that omits the list inherits the realm's defaultDefaultClientScopes (or
// Keycloak's built-in defaults). "openid" and undefined scopes are dropped.
func (c *Config) EffectiveDefaultScopes(client *ClientConfig) []string {
	var names []string
	switch {
	case client != nil && client.DefaultClientScopes != nil:
		names = client.DefaultClientScopes
	case c.Realm.DefaultDefaultClientScopes != nil:
		names = c.Realm.DefaultDefaultClientScopes
	default:
		names = builtinDefaultScopes
	}
	return c.definedScopes(names)
}

// EffectiveOptionalScopes is the optional-scope counterpart of
// EffectiveDefaultScopes. Scopes that are also defaults are dropped.
func (c *Config) EffectiveOptionalScopes(client *ClientConfig) []string {
	var names []string
	switch {
	case client != nil && client.OptionalClientScopes != nil:
		names = client.OptionalClientScopes
	case c.Realm.DefaultOptionalClientScopes != nil:
		names = c.Realm.DefaultOptionalClientScopes
	default:
		names = builtinOptionalScopes
	}
	defaults := toSet(c.EffectiveDefaultScopes(client))
	var out []string
	for _, n := range c.definedScopes(names) {
		if !defaults[n] {
			out = append(out, n)
		}
	}
	return out
}

func (c *Config) definedScopes(names []string) []string {
	out := make([]string, 0, len(names))
	seen := make(map[string]bool)
	for _, n := range names {
		if n == ScopeOpenID || seen[n] || c.FindClientScope(n) == nil {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// GrantScopes computes the scopes granted to client for a space-separated
// scope request, following Keycloak: "openid" if requested, all default
// client scopes, plus any requested optional client scopes. Requesting any
// other scope yields an error wrapping ErrInvalidScope.
func (c *Config) GrantScopes(client *ClientConfig, requested string) ([]string, error) {
	defaults := c.EffectiveDefaultScopes(client)
	optional := toSet(c.EffectiveOptionalScopes(client))
	defaultSet := toSet(defaults)

	req := strings.Fields(requested)
	reqSet := toSet(req)

	var invalid []string
	for _, s := range req {
		if s != ScopeOpenID && !defaultSet[s] && !optional[s] {
			invalid = append(invalid, s)
		}
	}
	if len(invalid) > 0 {
		return nil, &ScopeError{Invalid: invalid}
	}

	var granted []string
	if reqSet[ScopeOpenID] {
		granted = append(granted, ScopeOpenID)
	}
	granted = append(granted, defaults...)
	seen := toSet(granted)
	for _, s := range req {
		if optional[s] && !seen[s] {
			seen[s] = true
			granted = append(granted, s)
		}
	}
	return granted, nil
}

// TokenScope renders the "scope" claim/response value for a granted scope
// list: "openid" (if granted) plus scopes whose include.in.token.scope is
// not "false".
func (c *Config) TokenScope(granted []string) string {
	out := make([]string, 0, len(granted))
	for _, s := range granted {
		if s == ScopeOpenID || c.FindClientScope(s).IncludeInTokenScope() {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}

// HasScope reports whether the space-separated scope string contains name
// as an exact entry.
func HasScope(scope, name string) bool {
	for _, s := range strings.Fields(scope) {
		if s == name {
			return true
		}
	}
	return false
}

// EffectiveMappers returns the protocol mappers that apply to a token: the
// client's own mappers followed by the mappers of each granted client scope.
func (c *Config) EffectiveMappers(client *ClientConfig, granted []string) []ProtocolMapperConfig {
	var out []ProtocolMapperConfig
	if client != nil {
		out = append(out, client.ProtocolMappers...)
	}
	for _, name := range granted {
		if s := c.FindClientScope(name); s != nil {
			out = append(out, s.ProtocolMappers...)
		}
	}
	filtered := out[:0]
	for _, m := range out {
		if m.Protocol == "" || m.Protocol == protocolOIDC {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

// ResolveClaims returns attribute-mapper claims for the target token
// ("id.token", "access.token", "userinfo.token") using the client's and the
// granted scopes' protocol mappers.
func (c *Config) ResolveClaims(client *ClientConfig, granted []string, user *UserConfig, target string) map[string]any {
	return resolveAttributeMappers(c.EffectiveMappers(client, granted), user, target)
}

// Audiences returns the audiences contributed by oidc-audience-mapper
// entries for the target token ("access.token" or "id.token"). As in
// Keycloak, "included.client.audience" takes precedence over
// "included.custom.audience".
func (c *Config) Audiences(client *ClientConfig, granted []string, target string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, m := range c.EffectiveMappers(client, granted) {
		if m.ProtocolMapper != "oidc-audience-mapper" || !mapperIncludedIn(m, target) {
			continue
		}
		aud := strings.TrimSpace(m.Config["included.client.audience"])
		if aud == "" {
			aud = strings.TrimSpace(m.Config["included.custom.audience"])
		}
		if aud == "" || seen[aud] {
			continue
		}
		seen[aud] = true
		out = append(out, aud)
	}
	return out
}

// AccessTokenAudience returns the access token "aud": only the audiences
// added by audience mappers (Keycloak does not add the requesting client;
// it appears as "azp"). Nil when there are none.
func (c *Config) AccessTokenAudience(client *ClientConfig, granted []string) []string {
	return c.Audiences(client, granted, "access.token")
}

// IDTokenAudience returns the ID token "aud": the client itself followed by
// audiences from mappers with id.token.claim=true.
func (c *Config) IDTokenAudience(client *ClientConfig, granted []string) []string {
	if client == nil {
		return nil
	}
	aud := []string{client.ClientID}
	for _, a := range c.Audiences(client, granted, "id.token") {
		if a != client.ClientID {
			aud = append(aud, a)
		}
	}
	return aud
}

// SupportedScopes returns the scopes advertised in discovery: "openid" plus
// every defined OIDC client scope that is included in the token scope.
func (c *Config) SupportedScopes() []string {
	out := []string{ScopeOpenID}
	for _, s := range c.clientScopes() {
		if (s.Protocol == "" || s.Protocol == protocolOIDC) && s.IncludeInTokenScope() && s.Name != ScopeOpenID {
			out = append(out, s.Name)
		}
	}
	return out
}

// mapperIncludedIn reports whether a mapper applies to the given token
// target, e.g. "access.token" -> config "access.token.claim" == "true".
func mapperIncludedIn(m ProtocolMapperConfig, target string) bool {
	return strings.EqualFold(m.Config[target+".claim"], "true")
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
