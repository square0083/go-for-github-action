package user

import (
	"strings"
	"testing"
	"time"
)

func TestHashPasswordNotPlaintextAndUnique(t *testing.T) {
	h1, err := hashPassword("s3cret-pass")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if strings.Contains(h1, "s3cret-pass") {
		t.Fatal("hash must not contain the plaintext password")
	}
	if !strings.HasPrefix(h1, "$2") {
		t.Fatalf("expected bcrypt prefix, got %q", h1)
	}
	h2, _ := hashPassword("s3cret-pass")
	if h1 == h2 {
		t.Fatal("bcrypt should embed a random salt, so equal passwords hash differently")
	}
}

func TestVerifyPassword(t *testing.T) {
	h, _ := hashPassword("right-password")
	if !verifyPassword("right-password", h) {
		t.Fatal("correct password should verify")
	}
	if verifyPassword("wrong-password", h) {
		t.Fatal("wrong password must not verify")
	}
}

func TestTokenRoundTrip(t *testing.T) {
	tm, err := NewTokenManager("unit-test-secret", time.Hour)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	tok, err := tm.Issue(42, RoleAdmin)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := tm.Parse(tok)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.UserID != 42 || claims.Role != RoleAdmin {
		t.Fatalf("claims mismatch: %+v", claims)
	}
}

func TestTokenRejectsWrongSecret(t *testing.T) {
	tm, _ := NewTokenManager("secret-a", time.Hour)
	tok, _ := tm.Issue(1, RoleUser)
	other, _ := NewTokenManager("secret-b", time.Hour)
	if _, err := other.Parse(tok); err == nil {
		t.Fatal("token signed with a different secret must be rejected")
	}
}

func TestTokenRejectsExpired(t *testing.T) {
	tm, _ := NewTokenManager("unit-test-secret", -time.Minute)
	tok, _ := tm.Issue(1, RoleUser)
	if _, err := tm.Parse(tok); err == nil {
		t.Fatal("expired token must be rejected")
	}
}

func TestTokenManagerRejectsEmptySecret(t *testing.T) {
	if _, err := NewTokenManager("", time.Hour); err == nil {
		t.Fatal("empty secret must be rejected")
	}
}
