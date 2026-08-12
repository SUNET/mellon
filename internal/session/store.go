package session

import (
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"

	"github.com/google/uuid"
)

type AuthCode struct {
	Code          string
	ClientID      string
	RedirectURI   string
	Scope         string
	Nonce         string
	Username      string
	CodeChallenge string
	ChallengeMethod string
	ExpiresAt     time.Time
}

type RefreshToken struct {
	Token     string
	ClientID  string
	Username  string
	Scope     string
	ExpiresAt time.Time
}

type AccessToken struct {
	Token     string
	ClientID  string
	Username  string
	Scope     string
	ExpiresAt time.Time
}

type Store struct {
	mu            sync.RWMutex
	codes         map[string]*AuthCode
	refreshTokens map[string]*RefreshToken
	accessTokens  map[string]*AccessToken
}

func NewStore() *Store {
	return &Store{
		codes:         make(map[string]*AuthCode),
		refreshTokens: make(map[string]*RefreshToken),
		accessTokens:  make(map[string]*AccessToken),
	}
}

func (s *Store) CreateCode(clientID, redirectURI, scope, nonce, username, codeChallenge, challengeMethod string, ttl time.Duration) string {
	code := uuid.New().String()
	s.mu.Lock()
	s.codes[code] = &AuthCode{
		Code:            code,
		ClientID:        clientID,
		RedirectURI:     redirectURI,
		Scope:           scope,
		Nonce:           nonce,
		Username:        username,
		CodeChallenge:   codeChallenge,
		ChallengeMethod: challengeMethod,
		ExpiresAt:       time.Now().Add(ttl),
	}
	s.mu.Unlock()
	return code
}

func (s *Store) ExchangeCode(code, codeVerifier string) *AuthCode {
	s.mu.Lock()
	defer s.mu.Unlock()

	ac, ok := s.codes[code]
	if !ok || time.Now().After(ac.ExpiresAt) {
		delete(s.codes, code)
		return nil
	}

	if ac.CodeChallenge != "" {
		if !verifyPKCE(ac.CodeChallenge, ac.ChallengeMethod, codeVerifier) {
			return nil
		}
	}

	delete(s.codes, code)
	return ac
}

func (s *Store) CreateRefreshToken(clientID, username, scope string, ttl time.Duration) string {
	token := uuid.New().String()
	s.mu.Lock()
	s.refreshTokens[token] = &RefreshToken{
		Token:     token,
		ClientID:  clientID,
		Username:  username,
		Scope:     scope,
		ExpiresAt: time.Now().Add(ttl),
	}
	s.mu.Unlock()
	return token
}

func (s *Store) ValidateRefreshToken(token string) *RefreshToken {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rt, ok := s.refreshTokens[token]
	if !ok || time.Now().After(rt.ExpiresAt) {
		return nil
	}
	return rt
}

func (s *Store) RevokeRefreshToken(token string) {
	s.mu.Lock()
	delete(s.refreshTokens, token)
	s.mu.Unlock()
}

func (s *Store) StoreAccessToken(tokenStr, clientID, username, scope string, ttl time.Duration) {
	s.mu.Lock()
	s.accessTokens[tokenStr] = &AccessToken{
		Token:     tokenStr,
		ClientID:  clientID,
		Username:  username,
		Scope:     scope,
		ExpiresAt: time.Now().Add(ttl),
	}
	s.mu.Unlock()
}

func (s *Store) ValidateAccessToken(token string) *AccessToken {
	s.mu.RLock()
	defer s.mu.RUnlock()

	at, ok := s.accessTokens[token]
	if !ok || time.Now().After(at.ExpiresAt) {
		return nil
	}
	return at
}

func verifyPKCE(challenge, method, verifier string) bool {
	if verifier == "" {
		return false
	}
	switch method {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		return computed == challenge
	case "plain":
		return verifier == challenge
	default:
		return false
	}
}
