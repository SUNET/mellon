package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/masv3971/mellon/internal/config"
	opcrypto "github.com/masv3971/mellon/internal/crypto"
	"github.com/masv3971/mellon/internal/session"
)

func TestRoutes_Preflight(t *testing.T) {
	cfg := &config.Config{
		Issuer: "http://localhost:8080",
		Realm:  config.RealmConfig{Realm: "test"},
	}
	kp, err := opcrypto.GenerateKeyPair(opcrypto.RS256, "test-kid")
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter(cfg, kp, session.NewStore())

	tests := []struct {
		path    string
		methods string
	}{
		{"/realms/test/protocol/openid-connect/token", "POST, OPTIONS"},
		{"/realms/test/protocol/openid-connect/userinfo", "GET, POST, OPTIONS"},
		{"/realms/test/protocol/openid-connect/certs", "GET, OPTIONS"},
		{"/realms/test/.well-known/openid-configuration", "GET, OPTIONS"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, tt.path, nil)
			req.Header.Set("Origin", "http://localhost:3000")
			req.Header.Set("Access-Control-Request-Method", "POST")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204", w.Code)
			}
			if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
				t.Errorf("Access-Control-Allow-Origin = %q", got)
			}
			if got := w.Header().Get("Access-Control-Allow-Methods"); got != tt.methods {
				t.Errorf("Access-Control-Allow-Methods = %q, want %q", got, tt.methods)
			}
		})
	}

	t.Run("no CORS on authorize", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/realms/test/protocol/openid-connect/auth", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("Access-Control-Allow-Origin = %q, want empty", got)
		}
	})
}
