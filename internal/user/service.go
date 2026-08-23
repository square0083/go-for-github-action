package user

import (
	"context"
	"errors"
	"fmt"
)

// ServiceError is an application-level error carrying an HTTP status and a
// stable machine-readable code for the unified error response.
type ServiceError struct {
	Status  int
	Code    string
	Message string
}

func (e *ServiceError) Error() string { return e.Message }

// NewServiceError builds a ServiceError.
func NewServiceError(status int, code, msg string) *ServiceError {
	return &ServiceError{Status: status, Code: code, Message: msg}
}

// Common service errors.
var (
	ErrNotFound        = NewServiceError(404, "not_found", "user not found")
	ErrConflict        = NewServiceError(409, "conflict", "username or email already in use")
	ErrForbidden       = NewServiceError(403, "forbidden", "insufficient permissions")
	ErrInvalidInput    = NewServiceError(400, "invalid_input", "invalid request")
	ErrAuth            = NewServiceError(401, "unauthorized", "invalid credentials")
	ErrUnauthenticated = NewServiceError(401, "unauthenticated", "authentication required")
)

// Service implements business logic and permission rules on top of a Store.
type Service struct {
	store Store
	tm    *TokenManager
}

// NewService wires a Service to its store and token manager.
func NewService(store Store, tm *TokenManager) *Service {
	return &Service{store: store, tm: tm}
}

// Create registers a new user and returns its sanitized form. The password is
// hashed before persistence.
func (s *Service) Create(ctx context.Context, in CreateUserInput) (*User, error) {
	in.Username = trimSpace(in.Username)
	in.Email = trimSpace(in.Email)
	if err := validateCreate(in); err != nil {
		return nil, NewServiceError(400, "invalid_input", err.Error())
	}
	if in.Role == "" {
		in.Role = RoleUser
	}
	hash, err := hashPassword(in.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	u := &User{Username: in.Username, Email: in.Email, PasswordHash: hash, Role: in.Role}
	if err := s.store.Create(ctx, u); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrConflict
		}
		return nil, err
	}
	return u, nil
}

// Authenticate verifies credentials and returns a signed token plus the
// authenticated user.
func (s *Service) Authenticate(ctx context.Context, username, password string) (string, *User, error) {
	u, err := s.store.GetByUsername(ctx, trimSpace(username))
	if errors.Is(err, errNotFound) || (u != nil && !verifyPassword(password, u.PasswordHash)) {
		return "", nil, ErrAuth
	}
	if err != nil {
		return "", nil, err
	}
	tok, err := s.tm.Issue(u.ID, u.Role)
	if err != nil {
		return "", nil, err
	}
	return tok, u, nil
}

// Get returns a user by id subject to access control.
func (s *Service) Get(ctx context.Context, actor *Claims, id int64) (*User, error) {
	if !actor.CanView(id) {
		return nil, ErrForbidden
	}
	u, err := s.store.GetByID(ctx, id)
	if errors.Is(err, errNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// List returns a page of users. Regular users are limited to their own record.
func (s *Service) List(ctx context.Context, actor *Claims, f ListFilter) ([]*User, int, error) {
	if actor.Role != RoleAdmin {
		// A non-admin may only see their own account.
		f.Username = ""
		f.Email = ""
		rows, _, err := s.store.List(ctx, ListFilter{})
		if err != nil {
			return nil, 0, err
		}
		self := (*User)(nil)
		for _, r := range rows {
			if r.ID == actor.UserID {
				self = r
				break
			}
		}
		if self == nil {
			return []*User{}, 0, nil
		}
		return []*User{self}, 1, nil
	}
	return s.store.List(ctx, f)
}

// Update modifies a user subject to access control and field permissions.
func (s *Service) Update(ctx context.Context, actor *Claims, id int64, in UpdateUserInput) (*User, error) {
	if actor.Role != RoleAdmin && actor.UserID != id {
		return nil, ErrForbidden
	}
	if err := validateUpdate(in); err != nil {
		return nil, NewServiceError(400, "invalid_input", err.Error())
	}
	u, err := s.store.GetByID(ctx, id)
	if errors.Is(err, errNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	// A non-admin may never change roles (self-elevation guard).
	if in.Role != "" && actor.Role != RoleAdmin && in.Role != u.Role {
		return nil, ErrForbidden
	}
	if in.Username != "" {
		u.Username = trimSpace(in.Username)
	}
	if in.Email != "" {
		u.Email = trimSpace(in.Email)
	}
	if in.Role != "" {
		u.Role = in.Role
	}
	if err := s.store.Update(ctx, u); err != nil {
		if errors.Is(err, errNotFound) {
			return nil, ErrNotFound
		}
		if isUniqueViolation(err) {
			return nil, ErrConflict
		}
		return nil, err
	}
	return u, nil
}

// Delete soft-deletes a user. Admin-only.
func (s *Service) Delete(ctx context.Context, actor *Claims, id int64) error {
	if actor.Role != RoleAdmin {
		return ErrForbidden
	}
	if err := s.store.Delete(ctx, id); errors.Is(err, errNotFound) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	return nil
}

// CanView reports whether the actor may view the given user id.
func (c *Claims) CanView(id int64) bool {
	return c.Role == RoleAdmin || c.UserID == id
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n') {
		end--
	}
	return s[start:end]
}
