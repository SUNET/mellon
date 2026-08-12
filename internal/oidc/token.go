package oidc

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/masv3971/mellon/internal/config"
	opcrypto "github.com/masv3971/mellon/internal/crypto"
	"github.com/masv3971/mellon/internal/session"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type TokenError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func HandleToken(cfg *config.Config, kp *opcrypto.KeyPair, store *session.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			tokenError(w, "invalid_request", "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.ParseForm()
		grantType := r.FormValue("grant_type")

		switch grantType {
		case "authorization_code":
			handleAuthCodeGrant(w, r, cfg, kp, store)
		case "client_credentials":
			handleClientCredentialsGrant(w, r, cfg, kp, store)
		case "password":
			handlePasswordGrant(w, r, cfg, kp, store)
		case "refresh_token":
			handleRefreshTokenGrant(w, r, cfg, kp, store)
		default:
			tokenError(w, "unsupported_grant_type", "grant type not supported", http.StatusBadRequest)
		}
	}
}

func handleAuthCodeGrant(w http.ResponseWriter, r *http.Request, cfg *config.Config, kp *opcrypto.KeyPair, store *session.Store) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")
	clientID, clientSecret, ok := extractClientCredentials(r)
	if !ok {
		tokenError(w, "invalid_client", "missing client credentials", http.StatusUnauthorized)
		return
	}

	client := cfg.FindClient(clientID)
	if client == nil {
		tokenError(w, "invalid_client", "client not found", http.StatusUnauthorized)
		return
	}
	if !client.PublicClient && client.Secret != clientSecret {
		tokenError(w, "invalid_client", "invalid client secret", http.StatusUnauthorized)
		return
	}

	ac := store.ExchangeCode(code, codeVerifier)
	if ac == nil {
		tokenError(w, "invalid_grant", "invalid or expired authorization code", http.StatusBadRequest)
		return
	}
	if ac.RedirectURI != redirectURI {
		tokenError(w, "invalid_grant", "redirect_uri mismatch", http.StatusBadRequest)
		return
	}

	user := cfg.FindUser(ac.Username)
	issueTokens(w, cfg, kp, store, client, user, ac.Scope, ac.Nonce)
}

func handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request, cfg *config.Config, kp *opcrypto.KeyPair, store *session.Store) {
	clientID, clientSecret, ok := extractClientCredentials(r)
	if !ok {
		tokenError(w, "invalid_client", "missing client credentials", http.StatusUnauthorized)
		return
	}

	client := cfg.FindClient(clientID)
	if client == nil || client.Secret != clientSecret {
		tokenError(w, "invalid_client", "invalid credentials", http.StatusUnauthorized)
		return
	}
	if !client.ServiceAccountsEnabled {
		tokenError(w, "unauthorized_client", "client not authorized for client_credentials", http.StatusBadRequest)
		return
	}

	scope := r.FormValue("scope")
	if scope == "" {
		scope = strings.Join(client.DefaultClientScopes, " ")
	}

	now := time.Now()
	atClaims := opcrypto.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer + "/realms/" + cfg.Realm.Realm,
			Subject:   clientID,
			Audience:  jwt.ClaimStrings{clientID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(cfg.Realm.AccessTokenLifespan) * time.Second)),
			ID:        uuid.New().String(),
		},
		Scope:    scope,
		ClientID: clientID,
	}

	accessToken, err := kp.SignAccessToken(atClaims)
	if err != nil {
		tokenError(w, "server_error", "failed to sign token", http.StatusInternalServerError)
		return
	}

	store.StoreAccessToken(accessToken, clientID, "", scope, time.Duration(cfg.Realm.AccessTokenLifespan)*time.Second)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   cfg.Realm.AccessTokenLifespan,
		Scope:       scope,
	})
}

func handlePasswordGrant(w http.ResponseWriter, r *http.Request, cfg *config.Config, kp *opcrypto.KeyPair, store *session.Store) {
	clientID, clientSecret, ok := extractClientCredentials(r)
	if !ok {
		tokenError(w, "invalid_client", "missing client credentials", http.StatusUnauthorized)
		return
	}

	client := cfg.FindClient(clientID)
	if client == nil {
		tokenError(w, "invalid_client", "client not found", http.StatusUnauthorized)
		return
	}
	if !client.PublicClient && client.Secret != clientSecret {
		tokenError(w, "invalid_client", "invalid client secret", http.StatusUnauthorized)
		return
	}
	if !client.DirectAccessGrantsEnabled {
		tokenError(w, "unauthorized_client", "client not authorized for direct access grants", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	user := cfg.ValidateUserPassword(username, password)
	if user == nil {
		tokenError(w, "invalid_grant", "invalid user credentials", http.StatusUnauthorized)
		return
	}

	scope := r.FormValue("scope")
	if scope == "" {
		scope = strings.Join(client.DefaultClientScopes, " ")
	}

	issueTokens(w, cfg, kp, store, client, user, scope, "")
}

func handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, cfg *config.Config, kp *opcrypto.KeyPair, store *session.Store) {
	refreshToken := r.FormValue("refresh_token")
	clientID, clientSecret, ok := extractClientCredentials(r)
	if !ok {
		tokenError(w, "invalid_client", "missing client credentials", http.StatusUnauthorized)
		return
	}

	client := cfg.FindClient(clientID)
	if client == nil {
		tokenError(w, "invalid_client", "client not found", http.StatusUnauthorized)
		return
	}
	if !client.PublicClient && client.Secret != clientSecret {
		tokenError(w, "invalid_client", "invalid client secret", http.StatusUnauthorized)
		return
	}

	rt := store.ValidateRefreshToken(refreshToken)
	if rt == nil || rt.ClientID != clientID {
		tokenError(w, "invalid_grant", "invalid refresh token", http.StatusBadRequest)
		return
	}

	store.RevokeRefreshToken(refreshToken)

	user := cfg.FindUser(rt.Username)
	issueTokens(w, cfg, kp, store, client, user, rt.Scope, "")
}

func issueTokens(w http.ResponseWriter, cfg *config.Config, kp *opcrypto.KeyPair, store *session.Store, client *config.ClientConfig, user *config.UserConfig, scope, nonce string) {
	now := time.Now()
	issuer := cfg.Issuer + "/realms/" + cfg.Realm.Realm
	sub := client.ClientID
	username := ""
	email := ""
	emailVerified := false
	givenName := ""
	familyName := ""
	name := ""

	if user != nil {
		sub = user.Username
		username = user.Username
		email = user.Email
		emailVerified = user.EmailVerified
		givenName = user.FirstName
		familyName = user.LastName
		if givenName != "" || familyName != "" {
			name = strings.TrimSpace(givenName + " " + familyName)
		}
	}

	atClaims := opcrypto.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{client.ClientID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(cfg.Realm.AccessTokenLifespan) * time.Second)),
			ID:        uuid.New().String(),
		},
		Scope:             scope,
		ClientID:          client.ClientID,
		PreferredUsername: username,
		Email:             email,
		EmailVerified:     emailVerified,
		Extra:             client.ResolveMappers(user, "access.token"),
	}

	accessToken, err := kp.SignAccessToken(atClaims)
	if err != nil {
		tokenError(w, "server_error", "failed to sign access token", http.StatusInternalServerError)
		return
	}

	store.StoreAccessToken(accessToken, client.ClientID, username, scope, time.Duration(cfg.Realm.AccessTokenLifespan)*time.Second)

	resp := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   cfg.Realm.AccessTokenLifespan,
		Scope:       scope,
	}

	// Issue refresh token
	if strings.Contains(scope, "offline_access") || client.StandardFlowEnabled {
		resp.RefreshToken = store.CreateRefreshToken(
			client.ClientID, username, scope,
			time.Duration(cfg.Realm.RefreshTokenLifespan)*time.Second,
		)
	}

	// Issue ID token if openid scope requested
	if strings.Contains(scope, "openid") {
		idClaims := opcrypto.IDTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   sub,
				Audience:  jwt.ClaimStrings{client.ClientID},
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(cfg.Realm.AccessTokenLifespan) * time.Second)),
				ID:        uuid.New().String(),
			},
			Nonce:         nonce,
			AuthTime:      now.Unix(),
			ACR:           "1",
			AZP:           client.ClientID,
			Name:          name,
			GivenName:     givenName,
			FamilyName:    familyName,
			Email:         email,
			EmailVerified: emailVerified,
			Extra:         client.ResolveMappers(user, "id.token"),
		}
		idToken, err := kp.SignIDToken(idClaims)
		if err != nil {
			tokenError(w, "server_error", "failed to sign id token", http.StatusInternalServerError)
			return
		}
		resp.IDToken = idToken
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func extractClientCredentials(r *http.Request) (clientID, clientSecret string, ok bool) {
	// Try HTTP Basic Auth first
	if id, secret, basicOk := r.BasicAuth(); basicOk {
		return id, secret, true
	}
	// Fall back to form values
	clientID = r.FormValue("client_id")
	clientSecret = r.FormValue("client_secret")
	if clientID != "" {
		return clientID, clientSecret, true
	}
	return "", "", false
}

func tokenError(w http.ResponseWriter, errCode, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(TokenError{Error: errCode, Description: description})
}

func codeTTL(cfg *config.Config) time.Duration {
	return time.Duration(cfg.Realm.AccessCodeLifespan) * time.Second
}
