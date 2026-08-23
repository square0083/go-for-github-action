package user

import (
	"fmt"
	"strings"
	"time"
)

// Role identifies the permission tier of a user account.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// User is the persisted representation of an account. PasswordHash is the
// bcrypt digest and must never be serialized to API responses.
type User struct {
	ID           int64      `json:"id"`
	Username     string     `json:"username"`
	Email        string     `json:"email"`
	Role         string     `json:"role"`
	PasswordHash string     `json:"-"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"` // non-nil => soft-deleted
}

// Sanitized returns a copy of u with all sensitive fields removed, safe to
// send to API clients.
func (u *User) Sanitized() *User {
	out := *u
	out.PasswordHash = ""
	return &out
}

// validateCreate enforces creation invariants: a plaintext password is
// required and must meet the minimum length; role must be one of the known
// values.
func validateCreate(in CreateUserInput) error {
	if err := validateUsername(in.Username); err != nil {
		return err
	}
	if err := validateEmail(in.Email); err != nil {
		return err
	}
	if len(in.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if in.Role == "" {
		in.Role = RoleUser
	}
	if in.Role != RoleAdmin && in.Role != RoleUser {
		return fmt.Errorf("role must be %q or %q", RoleAdmin, RoleUser)
	}
	return nil
}

// validateUpdate enforces invariants for partial updates. Empty string fields
// are left unchanged by the caller.
func validateUpdate(in UpdateUserInput) error {
	if in.Username != "" {
		if err := validateUsername(in.Username); err != nil {
			return err
		}
	}
	if in.Email != "" {
		if err := validateEmail(in.Email); err != nil {
			return err
		}
	}
	if in.Role != "" && in.Role != RoleAdmin && in.Role != RoleUser {
		return fmt.Errorf("role must be %q or %q", RoleAdmin, RoleUser)
	}
	return nil
}

func validateUsername(s string) error {
	s = strings.TrimSpace(s)
	if len(s) < 3 {
		return fmt.Errorf("username must be at least 3 characters")
	}
	if len(s) > 50 {
		return fmt.Errorf("username must be at most 50 characters")
	}
	return nil
}

func validateEmail(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("email is required")
	}
	if !strings.Contains(s, "@") {
		return fmt.Errorf("email must contain '@'")
	}
	return nil
}
