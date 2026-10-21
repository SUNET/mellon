package oidc

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/masv3971/mellon/internal/config"
	"github.com/masv3971/mellon/internal/session"
)

func HandleAuthorize(cfg *config.Config, store *session.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID := r.URL.Query().Get("client_id")
		redirectURI := r.URL.Query().Get("redirect_uri")
		responseType := r.URL.Query().Get("response_type")
		scope := r.URL.Query().Get("scope")
		state := r.URL.Query().Get("state")
		nonce := r.URL.Query().Get("nonce")
		codeChallenge := r.URL.Query().Get("code_challenge")
		challengeMethod := r.URL.Query().Get("code_challenge_method")

		if responseType != "code" {
			http.Error(w, "unsupported_response_type", http.StatusBadRequest)
			return
		}

		client := cfg.FindClient(clientID)
		if client == nil {
			http.Error(w, "invalid_client", http.StatusBadRequest)
			return
		}

		if !validateRedirectURI(client, redirectURI) {
			http.Error(w, "invalid_redirect_uri", http.StatusBadRequest)
			return
		}

		if codeChallenge != "" && challengeMethod == "" {
			challengeMethod = "plain"
		}

		// Keycloak rejects unknown scopes before authentication by
		// redirecting back to the client with error=invalid_scope.
		if _, err := cfg.GrantScopes(client, scope); err != nil {
			redirectError(w, r, redirectURI, "invalid_scope", err.Error(), state)
			return
		}

		// Store auth request params in query and redirect to login page
		loginURL := fmt.Sprintf("/realms/%s/login?%s", cfg.Realm.Realm, r.URL.RawQuery)
		http.Redirect(w, r, loginURL, http.StatusFound)
		_ = store
		_ = nonce
	}
}

// redirectError sends an OAuth 2.0 authorization error response to the
// client's redirect URI (RFC 6749 section 4.1.2.1).
func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, errCode, description, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, errCode, http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", errCode)
	if description != "" {
		q.Set("error_description", description)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func validateRedirectURI(client *config.ClientConfig, uri string) bool {
	if uri == "" {
		return false
	}
	for _, allowed := range client.RedirectURIs {
		if allowed == uri {
			return true
		}
		// Support simple wildcard matching (e.g., http://localhost:3000/*)
		if strings.HasSuffix(allowed, "*") {
			prefix := strings.TrimSuffix(allowed, "*")
			if strings.HasPrefix(uri, prefix) {
				return true
			}
		}
	}
	return false
}

func CompleteAuthorize(w http.ResponseWriter, r *http.Request, cfg *config.Config, store *session.Store, username string) {
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	scope := r.FormValue("scope")
	state := r.FormValue("state")
	nonce := r.FormValue("nonce")
	codeChallenge := r.FormValue("code_challenge")
	challengeMethod := r.FormValue("code_challenge_method")

	// The login form round-trips the request parameters, so re-validate
	// them rather than trusting the posted values.
	client := cfg.FindClient(clientID)
	if client == nil {
		http.Error(w, "invalid_client", http.StatusBadRequest)
		return
	}
	if !validateRedirectURI(client, redirectURI) {
		http.Error(w, "invalid_redirect_uri", http.StatusBadRequest)
		return
	}
	granted, err := cfg.GrantScopes(client, scope)
	if err != nil {
		redirectError(w, r, redirectURI, "invalid_scope", err.Error(), state)
		return
	}

	code := store.CreateCode(
		clientID, redirectURI, strings.Join(granted, " "), nonce, username,
		codeChallenge, challengeMethod,
		codeTTL(cfg),
	)

	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
