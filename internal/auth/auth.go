// Package auth handles authentication: password hashing, access tokens and
// login throttling. It answers "who is this?"; what they may do is decided by
// the authz package.
package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	MinPasswordLen = 10
	MaxPasswordLen = 72 // bcrypt silently ignores bytes past 72
)

var ErrInvalidToken = errors.New("invalid token")

type Service struct {
	secret    []byte
	issuer    string
	ttl       time.Duration
	dummyHash string // compared against when the user does not exist, to equalise timing
}

// NewService returns a token service. secret must be at least 32 bytes.
func NewService(secret []byte, issuer string, ttl time.Duration) (*Service, error) {
	if len(secret) < 32 {
		return nil, errors.New("jwt secret must be at least 32 bytes")
	}
	junk := make([]byte, 16)
	if _, err := rand.Read(junk); err != nil {
		return nil, err
	}
	dummy, err := bcrypt.GenerateFromPassword(junk, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return &Service{secret: secret, issuer: issuer, ttl: ttl, dummyHash: string(dummy)}, nil
}

// Issue returns a signed access token for userID and its expiry.
func (s *Service) Issue(userID string) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(s.ttl)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   userID,
		Issuer:    s.issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(exp),
	})
	signed, err := tok.SignedString(s.secret)
	return signed, exp, err
}

// Verify validates signature, algorithm, issuer and expiry, returning the subject.
func (s *Service) Verify(token string) (string, error) {
	claims := &jwt.RegisteredClaims{}
	_, err := jwt.ParseWithClaims(token, claims,
		func(*jwt.Token) (any, error) { return s.secret, nil },
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(s.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil || claims.Subject == "" {
		return "", fmt.Errorf("%w", ErrInvalidToken)
	}
	return claims.Subject, nil
}

// DummyHash is a valid bcrypt hash to compare against for unknown users.
func (s *Service) DummyHash() string { return s.dummyHash }

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}
