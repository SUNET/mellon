package oidc

import (
	"net/http"
)

const (
	corsAllowHeaders = "Authorization, Content-Type"
	corsMaxAge       = "3600"
)

// originAllowed reports whether origin matches one of the allowed origins
// exactly, or whether allowed contains the "*" wildcard.
func originAllowed(origin string, allowed []string) bool {
	if origin == "" {
		return false
	}
	for _, a := range allowed {
		if a == "*" || a == origin {
			return true
		}
	}
	return false
}

// setCORS echoes the request Origin in Access-Control-Allow-Origin when it is
// in allowed. Vary: Origin is always added since the response depends on it.
func setCORS(w http.ResponseWriter, r *http.Request, allowed []string) {
	w.Header().Add("Vary", "Origin")
	origin := r.Header.Get("Origin")
	if originAllowed(origin, allowed) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
}

// setCORSAnyOrigin echoes any request Origin. Used for public, non-sensitive
// endpoints (discovery, JWKS) and as a provisional header that a handler may
// later revoke with clearCORS.
func setCORSAnyOrigin(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "Origin")
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
}

// clearCORS removes a previously set Access-Control-Allow-Origin header.
func clearCORS(w http.ResponseWriter) {
	w.Header().Del("Access-Control-Allow-Origin")
}

// HandlePreflight answers CORS preflight (OPTIONS) requests. Like Keycloak,
// preflight is permissive: the actual request enforces the client's origins.
func HandlePreflight(methods string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Add("Vary", "Origin")
		if origin := r.Header.Get("Origin"); origin != "" {
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Methods", methods)
			h.Set("Access-Control-Allow-Headers", corsAllowHeaders)
			h.Set("Access-Control-Max-Age", corsMaxAge)
		}
		h.Set("Allow", methods)
		w.WriteHeader(http.StatusNoContent)
	}
}
