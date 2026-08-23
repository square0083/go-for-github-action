package user

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// ErrInvalidCredentials is returned by Authenticate on bad username/password.
var ErrInvalidCredentials = errors.New("invalid credentials")

// hashPassword derives a bcrypt digest. bcrypt embeds a random salt, so the
// same plaintext yields different hashes across calls.
func hashPassword(plain string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(h), nil
}

// verifyPassword reports whether plain matches the stored bcrypt hash.
func verifyPassword(plain, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// Claims is the JWT payload carried in auth tokens.
type Claims struct {
	UserID int64  `json:"uid"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// TokenManager issues and validates HMAC-signed JWTs.
type TokenManager struct {
	secret []byte
	ttl    time.Duration
}

// NewTokenManager builds a manager with the given signing secret and
// token lifetime. A zero secret is rejected to avoid unsigned tokens.
func NewTokenManager(secret string, ttl time.Duration) (*TokenManager, error) {
	if secret == "" {
		return nil, errors.New("token secret must not be empty")
	}
	return &TokenManager{secret: []byte(secret), ttl: ttl}, nil
}

// Issue signs a token for the given subject and role.
func (m *TokenManager) Issue(userID int64, role string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", userID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return s, nil
}

// Parse validates a token's signature and expiry and returns its claims.
func (m *TokenManager) Parse(raw string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return m.secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	return claims, nil
}
