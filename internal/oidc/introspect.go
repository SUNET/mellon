package oidc

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/masv3971/mellon/internal/config"
	opcrypto "github.com/masv3971/mellon/internal/crypto"
	"github.com/masv3971/mellon/internal/session"
)

type IntrospectResponse struct {
	Active    bool             `json:"active"`
	Scope     string           `json:"scope,omitempty"`
	ClientID  string           `json:"client_id,omitempty"`
	Username  string           `json:"username,omitempty"`
	TokenType string           `json:"token_type,omitempty"`
	Exp       int64            `json:"exp,omitempty"`
	Iat       int64            `json:"iat,omitempty"`
	Sub       string           `json:"sub,omitempty"`
	Iss       string           `json:"iss,omitempty"`
	Aud       jwt.ClaimStrings `json:"aud,omitempty"`
	Azp       string           `json:"azp,omitempty"`
	Typ       string           `json:"typ,omitempty"`
}

func HandleIntrospect(cfg *config.Config, kp *opcrypto.KeyPair, store *session.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Authenticate the requesting client
		clientID, clientSecret, ok := extractClientCredentials(r)
		if !ok {
			tokenError(w, "invalid_client", "missing client credentials", http.StatusUnauthorized)
			return
		}
		client := cfg.FindClient(clientID)
		if client == nil || (!client.PublicClient && client.Secret != clientSecret) {
			tokenError(w, "invalid_client", "invalid credentials", http.StatusUnauthorized)
			return
		}

		r.ParseForm()
		token := r.FormValue("token")
		if token == "" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(IntrospectResponse{Active: false})
			return
		}

		// Try JWT validation first
		parsed, err := kp.ValidateToken(token)
		if err == nil && parsed.Valid {
			claims := parsed.Claims
			exp, _ := claims.GetExpirationTime()
			iat, _ := claims.GetIssuedAt()
			sub, _ := claims.GetSubject()
			iss, _ := claims.GetIssuer()
			aud, _ := claims.GetAudience()
			var azp, typ string
			if mc, ok := claims.(jwt.MapClaims); ok {
				azp, _ = mc["azp"].(string)
				typ, _ = mc["typ"].(string)
			}

			// Check if token is in our store (for revocation support)
			at := store.ValidateAccessToken(token)
			if at == nil {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(IntrospectResponse{Active: false})
				return
			}

			resp := IntrospectResponse{
				Active:    true,
				Scope:     cfg.TokenScope(strings.Fields(at.Scope)),
				ClientID:  at.ClientID,
				Username:  at.Username,
				TokenType: "Bearer",
				Sub:       sub,
				Iss:       iss,
				Aud:       aud,
				Azp:       azp,
				Typ:       typ,
			}
			if exp != nil {
				resp.Exp = exp.Unix()
			}
			if iat != nil {
				resp.Iat = iat.Unix()
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Try as refresh token
		rt := store.ValidateRefreshToken(token)
		if rt != nil && time.Now().Before(rt.ExpiresAt) {
			resp := IntrospectResponse{
				Active:    true,
				Scope:     cfg.TokenScope(strings.Fields(rt.Scope)),
				ClientID:  rt.ClientID,
				Username:  rt.Username,
				TokenType: "refresh_token",
				Sub:       rt.Username,
				Iss:       cfg.Issuer + "/realms/" + cfg.Realm.Realm,
				Exp:       rt.ExpiresAt.Unix(),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(IntrospectResponse{Active: false})
	}
}
