package oidc

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/masv3971/mellon/internal/config"
	opcrypto "github.com/masv3971/mellon/internal/crypto"
	"github.com/masv3971/mellon/internal/session"
)

type UserInfoResponse struct {
	Sub               string         `json:"sub"`
	Name              string         `json:"name,omitempty"`
	GivenName         string         `json:"given_name,omitempty"`
	FamilyName        string         `json:"family_name,omitempty"`
	PreferredUsername string         `json:"preferred_username,omitempty"`
	Email             string         `json:"email,omitempty"`
	EmailVerified     bool           `json:"email_verified,omitempty"`
	Extra             map[string]any `json:"-"`
}

func (u UserInfoResponse) MarshalJSON() ([]byte, error) {
	type Alias UserInfoResponse
	base, err := json.Marshal(Alias(u))
	if err != nil {
		return nil, err
	}
	if len(u.Extra) == 0 {
		return base, nil
	}
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		return nil, err
	}
	for k, v := range u.Extra {
		if _, exists := m[k]; !exists {
			m[k] = v
		}
	}
	return json.Marshal(m)
}

func HandleUserInfo(cfg *config.Config, kp *opcrypto.KeyPair, store *session.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Provisionally allow any origin so 401s are readable by the browser;
		// once the token is known, restrict to its allowed-origins.
		setCORSAnyOrigin(w, r)

		token := extractBearerToken(r)
		if token == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		at := store.ValidateAccessToken(token)
		if at == nil {
			w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
			http.Error(w, "invalid_token", http.StatusUnauthorized)
			return
		}

		if origin := r.Header.Get("Origin"); origin != "" {
			if !originAllowed(origin, tokenAllowedOrigins(cfg, kp, token, at.ClientID)) {
				clearCORS(w)
			}
		}

		user := cfg.FindUser(at.Username)
		if user == nil {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}

		client := cfg.FindClient(at.ClientID)

		resp := UserInfoResponse{
			Sub: user.Username,
		}

		scope := at.Scope
		if config.HasScope(scope, "profile") {
			resp.PreferredUsername = user.Username
			resp.Name = strings.TrimSpace(user.FirstName + " " + user.LastName)
			resp.GivenName = user.FirstName
			resp.FamilyName = user.LastName
		}
		if config.HasScope(scope, "email") {
			resp.Email = user.Email
			resp.EmailVerified = user.EmailVerified
		}

		resp.Extra = cfg.ResolveClaims(client, strings.Fields(scope), user, "userinfo.token")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// tokenAllowedOrigins returns the allowed-origins claim of an access token.
// If the token cannot be parsed, it falls back to the issuing client's
// configured origins.
func tokenAllowedOrigins(cfg *config.Config, kp *opcrypto.KeyPair, token, clientID string) []string {
	parsed, err := kp.ValidateToken(token)
	if err != nil || !parsed.Valid {
		return cfg.FindClient(clientID).AllowedOrigins()
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil
	}
	raw, ok := claims["allowed-origins"].([]any)
	if !ok {
		return nil
	}
	origins := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			origins = append(origins, s)
		}
	}
	return origins
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}
