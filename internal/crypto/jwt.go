package crypto

import (
	"encoding/json"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type IDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce         string                 `json:"nonce,omitempty"`
	AuthTime      int64                  `json:"auth_time,omitempty"`
	ACR           string                 `json:"acr,omitempty"`
	AZP           string                 `json:"azp,omitempty"`
	Name          string                 `json:"name,omitempty"`
	GivenName     string                 `json:"given_name,omitempty"`
	FamilyName    string                 `json:"family_name,omitempty"`
	Email         string                 `json:"email,omitempty"`
	EmailVerified bool                   `json:"email_verified,omitempty"`
	Extra         map[string]any `json:"-"`
}

func (c IDTokenClaims) MarshalJSON() ([]byte, error) {
	type Alias IDTokenClaims
	base, err := json.Marshal(Alias(c))
	if err != nil {
		return nil, err
	}
	if len(c.Extra) == 0 {
		return base, nil
	}
	return mergeJSON(base, c.Extra)
}

type AccessTokenClaims struct {
	jwt.RegisteredClaims
	Scope             string                 `json:"scope,omitempty"`
	ClientID          string                 `json:"client_id,omitempty"`
	PreferredUsername string                 `json:"preferred_username,omitempty"`
	Email             string                 `json:"email,omitempty"`
	EmailVerified     bool                   `json:"email_verified,omitempty"`
	Extra             map[string]any `json:"-"`
}

func (c AccessTokenClaims) MarshalJSON() ([]byte, error) {
	type Alias AccessTokenClaims
	base, err := json.Marshal(Alias(c))
	if err != nil {
		return nil, err
	}
	if len(c.Extra) == 0 {
		return base, nil
	}
	return mergeJSON(base, c.Extra)
}

func mergeJSON(base []byte, extra map[string]any) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		return nil, err
	}
	for k, v := range extra {
		if _, exists := m[k]; !exists {
			m[k] = v
		}
	}
	return json.Marshal(m)
}

func (kp *KeyPair) SigningMethod() jwt.SigningMethod {
	switch kp.Algorithm {
	case RS256:
		return jwt.SigningMethodRS256
	case ES256:
		return jwt.SigningMethodES256
	case EdDSA:
		return jwt.SigningMethodEdDSA
	default:
		return jwt.SigningMethodRS256
	}
}

func (kp *KeyPair) SignIDToken(claims IDTokenClaims) (string, error) {
	token := jwt.NewWithClaims(kp.SigningMethod(), claims)
	token.Header["kid"] = kp.KID
	return token.SignedString(kp.PrivateKey)
}

func (kp *KeyPair) SignAccessToken(claims AccessTokenClaims) (string, error) {
	token := jwt.NewWithClaims(kp.SigningMethod(), claims)
	token.Header["kid"] = kp.KID
	return token.SignedString(kp.PrivateKey)
}

func (kp *KeyPair) ValidateToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return kp.PublicKey, nil
	}, jwt.WithTimeFunc(time.Now))
}
