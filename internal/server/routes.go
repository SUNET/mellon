package server

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/masv3971/mellon/internal/config"
	opcrypto "github.com/masv3971/mellon/internal/crypto"
	"github.com/masv3971/mellon/internal/login"
	"github.com/masv3971/mellon/internal/oidc"
	"github.com/masv3971/mellon/internal/session"
)

func NewRouter(cfg *config.Config, kp *opcrypto.KeyPair, store *session.Store) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "STATUS_OK"})
	})

	r.Route("/realms/{realm}", func(r chi.Router) {
		r.Get("/.well-known/openid-configuration", oidc.HandleDiscovery(cfg))

		r.Route("/protocol/openid-connect", func(r chi.Router) {
			r.Get("/auth", oidc.HandleAuthorize(cfg, store))
			r.Post("/token", oidc.HandleToken(cfg, kp, store))
			r.Post("/token/introspect", oidc.HandleIntrospect(cfg, kp, store))
			r.Get("/userinfo", oidc.HandleUserInfo(cfg, kp, store))
			r.Post("/userinfo", oidc.HandleUserInfo(cfg, kp, store))
			r.Get("/certs", oidc.HandleJWKS(kp))
			r.Get("/logout", oidc.HandleLogout())
			r.Post("/logout", oidc.HandleLogout())
		})

		r.Get("/login", login.HandleLoginPage(cfg))
		r.Post("/login", login.HandleLoginSubmit(cfg, store))
	})

	return r
}
