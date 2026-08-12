package login

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/masv3971/mellon/internal/config"
	"github.com/masv3971/mellon/internal/oidc"
	"github.com/masv3971/mellon/internal/session"
)

//go:embed login.html
var loginFS embed.FS

var loginTemplate = template.Must(template.ParseFS(loginFS, "login.html"))

type loginData struct {
	Error           string
	ClientID        string
	RedirectURI     string
	Scope           string
	State           string
	Nonce           string
	ResponseType    string
	CodeChallenge   string
	ChallengeMethod string
	Realm           string
}

func HandleLoginPage(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := loginData{
			ClientID:        r.URL.Query().Get("client_id"),
			RedirectURI:     r.URL.Query().Get("redirect_uri"),
			Scope:           r.URL.Query().Get("scope"),
			State:           r.URL.Query().Get("state"),
			Nonce:           r.URL.Query().Get("nonce"),
			ResponseType:    r.URL.Query().Get("response_type"),
			CodeChallenge:   r.URL.Query().Get("code_challenge"),
			ChallengeMethod: r.URL.Query().Get("code_challenge_method"),
			Realm:           cfg.Realm.Realm,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		loginTemplate.Execute(w, data)
	}
}

func HandleLoginSubmit(cfg *config.Config, store *session.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.ParseForm()

		username := r.FormValue("username")
		password := r.FormValue("password")

		user := cfg.ValidateUserPassword(username, password)
		if user == nil {
			data := loginData{
				Error:           "Invalid username or password",
				ClientID:        r.FormValue("client_id"),
				RedirectURI:     r.FormValue("redirect_uri"),
				Scope:           r.FormValue("scope"),
				State:           r.FormValue("state"),
				Nonce:           r.FormValue("nonce"),
				ResponseType:    r.FormValue("response_type"),
				CodeChallenge:   r.FormValue("code_challenge"),
				ChallengeMethod: r.FormValue("code_challenge_method"),
				Realm:           cfg.Realm.Realm,
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			loginTemplate.Execute(w, data)
			return
		}

		oidc.CompleteAuthorize(w, r, cfg, store, username)
	}
}
