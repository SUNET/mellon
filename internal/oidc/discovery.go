package oidc

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/masv3971/mellon/internal/config"
)

type DiscoveryResponse struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

func HandleDiscovery(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realm := chi.URLParam(r, "realm")
		if realm == "" {
			realm = cfg.Realm.Realm
		}

		base := cfg.Issuer + "/realms/" + realm + "/protocol/openid-connect"

		resp := DiscoveryResponse{
			Issuer:                cfg.Issuer + "/realms/" + realm,
			AuthorizationEndpoint: base + "/auth",
			TokenEndpoint:         base + "/token",
			IntrospectionEndpoint: base + "/token/introspect",
			UserinfoEndpoint:      base + "/userinfo",
			JwksURI:               base + "/certs",
			EndSessionEndpoint:    base + "/logout",
			ResponseTypesSupported: []string{
				"code",
				"id_token",
				"code id_token",
				"code token",
				"code id_token token",
			},
			SubjectTypesSupported:            []string{"public"},
			IDTokenSigningAlgValuesSupported:  []string{string(cfg.GetAlgorithm())},
			ScopesSupported:                  []string{"openid", "profile", "email", "offline_access"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
			ClaimsSupported: []string{
				"sub", "iss", "aud", "iat", "exp", "auth_time", "nonce",
				"name", "given_name", "family_name", "email", "email_verified",
				"preferred_username", "acr", "azp",
			},
			GrantTypesSupported:           []string{"authorization_code", "client_credentials", "password", "refresh_token"},
			ResponseModesSupported:        []string{"query", "fragment"},
			CodeChallengeMethodsSupported: []string{"plain", "S256"},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
