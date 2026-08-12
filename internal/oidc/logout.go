package oidc

import (
	"net/http"
	"net/url"
)

func HandleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("post_logout_redirect_uri")
		if redirectURI == "" {
			redirectURI = r.URL.Query().Get("redirect_uri")
		}

		if redirectURI != "" {
			u, err := url.Parse(redirectURI)
			if err == nil && (u.Scheme == "http" || u.Scheme == "https") {
				http.Redirect(w, r, redirectURI, http.StatusFound)
				return
			}
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Logged out"))
	}
}
