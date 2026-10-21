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

		// CORS: allow the browser to read the response (including errors)
		// only when the Origin is in the calling client's webOrigins.
		var allowed []string
		if clientID, _, ok := extractClientCredentials(r); ok {
			allowed = cfg.FindClient(clientID).AllowedOrigins()
		}
		setCORS(w, r, allowed)

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

	if ac.ClientID != client.ClientID {
		tokenError(w, "invalid_grant", "code was issued to another client", http.StatusBadRequest)
		return
	}

	user := cfg.FindUser(ac.Username)
	issueTokens(w, cfg, kp, store, client, user, strings.Fields(ac.Scope), ac.Nonce, true)
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

	granted, ok := grantScopes(w, cfg, client, r.FormValue("scope"))
	if !ok {
		return
	}

	// Keycloak does not issue refresh tokens for client_credentials by
	// default ("use.refresh.tokens.client.credentials" is off).
	issueTokens(w, cfg, kp, store, client, nil, granted, "", false)
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

	granted, ok := grantScopes(w, cfg, client, r.FormValue("scope"))
	if !ok {
		return
	}

	issueTokens(w, cfg, kp, store, client, user, granted, "", true)
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

	granted := strings.Fields(rt.Scope)
	if requested := r.FormValue("scope"); requested != "" {
		// Keycloak: a refresh request may narrow, but never widen, the
		// originally granted scopes.
		orig := make(map[string]bool, len(granted))
		for _, s := range granted {
			orig[s] = true
		}
		var invalid []string
		for _, s := range strings.Fields(requested) {
			if !orig[s] {
				invalid = append(invalid, s)
			}
		}
		if len(invalid) > 0 {
			tokenError(w, "invalid_scope", (&config.ScopeError{Invalid: invalid}).Error(), http.StatusBadRequest)
			return
		}
		narrowed, ok := grantScopes(w, cfg, client, requested)
		if !ok {
			return
		}
		var kept []string
		for _, s := range narrowed {
			if orig[s] {
				kept = append(kept, s)
			}
		}
		granted = kept
	}

	store.RevokeRefreshToken(refreshToken)

	user := cfg.FindUser(rt.Username)
	issueTokens(w, cfg, kp, store, client, user, granted, "", true)
}

// grantScopes applies the Keycloak scope rules for client and writes an
// invalid_scope error response on failure.
func grantScopes(w http.ResponseWriter, cfg *config.Config, client *config.ClientConfig, requested string) ([]string, bool) {
	granted, err := cfg.GrantScopes(client, requested)
	if err != nil {
		tokenError(w, "invalid_scope", err.Error(), http.StatusBadRequest)
		return nil, false
	}
	return granted, true
}

// issueTokens signs and returns the tokens for a grant. granted is the full
// list of granted scopes (including those hidden from the scope claim); it
// drives claim inclusion, protocol mappers and the audience.
func issueTokens(w http.ResponseWriter, cfg *config.Config, kp *opcrypto.KeyPair, store *session.Store, client *config.ClientConfig, user *config.UserConfig, granted []string, nonce string, withRefresh bool) {
	now := time.Now()
	issuer := cfg.Issuer + "/realms/" + cfg.Realm.Realm
	grantedStr := strings.Join(granted, " ")
	tokenScope := cfg.TokenScope(granted)
	hasProfile := config.HasScope(grantedStr, "profile")
	hasEmail := config.HasScope(grantedStr, "email")

	sub := client.ClientID
	username := ""
	var email, givenName, familyName, name string
	emailVerified := false

	if user != nil {
		sub = user.Username
		username = user.Username
		if hasEmail {
			email = user.Email
			emailVerified = user.EmailVerified
		}
		if hasProfile {
			givenName = user.FirstName
			familyName = user.LastName
			name = strings.TrimSpace(givenName + " " + familyName)
		}
	}
	preferredUsername := ""
	if hasProfile {
		preferredUsername = username
		if user == nil {
			// Keycloak's service-account user is named service-account-<clientId>.
			preferredUsername = "service-account-" + client.ClientID
		}
	}

	var accessAud jwt.ClaimStrings
	if auds := cfg.AccessTokenAudience(client, granted); len(auds) > 0 {
		accessAud = jwt.ClaimStrings(auds)
	}

	atClaims := opcrypto.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   sub,
			Audience:  accessAud,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(cfg.Realm.AccessTokenLifespan) * time.Second)),
			ID:        uuid.New().String(),
		},
		Typ:               "Bearer",
		AZP:               client.ClientID,
		Scope:             tokenScope,
		ClientID:          client.ClientID,
		PreferredUsername: preferredUsername,
		Name:              name,
		GivenName:         givenName,
		FamilyName:        familyName,
		Email:             email,
		EmailVerified:     emailVerified,
		AllowedOrigins:    client.AllowedOrigins(),
		Extra:             cfg.ResolveClaims(client, granted, user, "access.token"),
	}

	accessToken, err := kp.SignAccessToken(atClaims)
	if err != nil {
		tokenError(w, "server_error", "failed to sign access token", http.StatusInternalServerError)
		return
	}

	store.StoreAccessToken(accessToken, client.ClientID, username, grantedStr, time.Duration(cfg.Realm.AccessTokenLifespan)*time.Second)

	resp := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   cfg.Realm.AccessTokenLifespan,
		Scope:       tokenScope,
	}

	if withRefresh {
		resp.RefreshToken = store.CreateRefreshToken(
			client.ClientID, username, grantedStr,
			time.Duration(cfg.Realm.RefreshTokenLifespan)*time.Second,
		)
	}

	// Issue an ID token only when "openid" was requested.
	if config.HasScope(grantedStr, config.ScopeOpenID) {
		idAud := jwt.ClaimStrings(cfg.IDTokenAudience(client, granted))
		idClaims := opcrypto.IDTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   sub,
				Audience:  idAud,
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(cfg.Realm.AccessTokenLifespan) * time.Second)),
				ID:        uuid.New().String(),
			},
			Typ:               "ID",
			Nonce:             nonce,
			AuthTime:          now.Unix(),
			ACR:               "1",
			AZP:               client.ClientID,
			PreferredUsername: preferredUsername,
			Name:              name,
			GivenName:         givenName,
			FamilyName:        familyName,
			Email:             email,
			EmailVerified:     emailVerified,
			Extra:             cfg.ResolveClaims(client, granted, user, "id.token"),
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
