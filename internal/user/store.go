package user

import "context"

// Store is the persistence boundary for users. Implementations back it with
// SQLite today and can be swapped for PostgreSQL without touching callers.
type Store interface {
	// Create inserts a user and populates its ID and timestamps.
	Create(ctx context.Context, u *User) error
	// GetByID returns a non-deleted user by primary key.
	GetByID(ctx context.Context, id int64) (*User, error)
	// GetByUsername returns a non-deleted user by username.
	GetByUsername(ctx context.Context, username string) (*User, error)
	// GetByEmail returns a non-deleted user by email.
	GetByEmail(ctx context.Context, email string) (*User, error)
	// List returns a page of non-deleted users plus the total count of
	// matching rows (before pagination).
	List(ctx context.Context, f ListFilter) ([]*User, int, error)
	// Update persists mutable fields and bumps UpdatedAt.
	Update(ctx context.Context, u *User) error
	// Delete soft-deletes a user by id (sets DeletedAt).
	Delete(ctx context.Context, id int64) error
	// Close releases underlying resources.
	Close() error
}

// ListFilter constrains List results.
type ListFilter struct {
	Username string
	Email    string
	Limit    int // page size; <=0 treated as 10
	Offset   int
}

// CreateUserInput carries validated fields for Create.
type CreateUserInput struct {
	Username string
	Email    string
	Password string // plaintext, hashed before persistence
	Role     string
}

// UpdateUserInput carries validated mutable fields for Update. Empty strings
// mean "leave unchanged".
type UpdateUserInput struct {
	Username string
	Email    string
	Role     string
}
