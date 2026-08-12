package oidc

import (
	"encoding/json"
	"net/http"

	opcrypto "github.com/masv3971/mellon/internal/crypto"
)

func HandleJWKS(kp *opcrypto.KeyPair) http.HandlerFunc {
	jwks := opcrypto.JWKSet{Keys: []opcrypto.JWK{kp.JWK()}}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}
}
