package auth

import (
	"strings"
	"testing"
	"time"
)

var secret = []byte(strings.Repeat("s", 32))

func TestTokenRoundTrip(t *testing.T) {
	svc, _ := NewService(secret, "docvault", time.Minute)
	tok, _, err := svc.Issue("alice")
	if err != nil {
		t.Fatal(err)
	}
	if sub, err := svc.Verify(tok); err != nil || sub != "alice" {
		t.Fatalf("got %q, %v", sub, err)
	}
}

func TestTokenRejections(t *testing.T) {
	svc, _ := NewService(secret, "docvault", time.Minute)
	other, _ := NewService([]byte(strings.Repeat("x", 32)), "docvault", time.Minute)
	otherIssuer, _ := NewService(secret, "someone-else", time.Minute)
	expired, _ := NewService(secret, "docvault", -time.Minute)

	good, _, _ := svc.Issue("alice")
	cases := map[string]string{
		"wrong key":    mustIssue(other),
		"wrong issuer": mustIssue(otherIssuer),
		"expired":      mustIssue(expired),
		"tampered":     good[:len(good)-2] + "xx",
		"garbage":      "not.a.jwt",
		"empty":        "",
		"alg none":     "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSJ9.",
	}
	for name, tok := range cases {
		if _, err := svc.Verify(tok); err == nil {
			t.Errorf("%s: token accepted", name)
		}
	}
}

func mustIssue(s *Service) string {
	tok, _, _ := s.Issue("alice")
	return tok
}

func TestShortSecretRejected(t *testing.T) {
	if _, err := NewService([]byte("short"), "x", time.Minute); err == nil {
		t.Fatal("expected error")
	}
}

func TestPasswords(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse battery") || CheckPassword(h, "wrong") {
		t.Fatal("password check wrong")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(3, time.Hour)
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("attempt %d blocked", i)
		}
	}
	if l.Allow("k") {
		t.Fatal("4th attempt allowed")
	}
	if !l.Allow("other") {
		t.Fatal("other key should be independent")
	}
}
