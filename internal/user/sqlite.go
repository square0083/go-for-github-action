package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	sqlite "modernc.org/sqlite"
)

// sqliteStore implements Store backed by a SQLite database.
type sqliteStore struct {
	db *sql.DB
}

func NewSQLiteStore(path string) (Store, error) {
	dsn := path
	if path == ":memory:" {
		// A single connection keeps an in-memory DB alive across queries.
		dsn = "file::memory:?cache=shared"
	}
	if path != ":memory:" {
		dir := path
		if i := strings.LastIndexAny(dir, `/\`); i >= 0 {
			dir = dir[:i]
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create data dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// modernc sqlite requires a single writer at a time for correctness.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &sqliteStore{db: db}, nil
}

func migrate(db *sql.DB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS users (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	username     TEXT NOT NULL UNIQUE,
	email        TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	role         TEXT NOT NULL DEFAULT 'user',
	created_at   DATETIME NOT NULL,
	updated_at   DATETIME NOT NULL,
	deleted_at   DATETIME
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
`
	_, err := db.Exec(schema)
	if err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}
	return nil
}

const cols = "id, username, email, password_hash, role, created_at, updated_at, deleted_at"

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var deletedAt sql.NullTime
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Role,
		&u.CreatedAt, &u.UpdatedAt, &deletedAt); err != nil {
		return nil, err
	}
	if deletedAt.Valid {
		u.DeletedAt = &deletedAt.Time
	}
	return &u, nil
}

var errNotFound = errors.New("user not found")

func (s *sqliteStore) Create(ctx context.Context, u *User) error {
	now := time.Now().UTC()
	u.CreatedAt = now
	u.UpdatedAt = now
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, email, password_hash, role, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		u.Username, u.Email, u.PasswordHash, u.Role, u.CreatedAt, u.UpdatedAt)
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("last insert id: %w", err)
	}
	u.ID = id
	return nil
}

func (s *sqliteStore) GetByID(ctx context.Context, id int64) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+cols+` FROM users WHERE id = ? AND deleted_at IS NULL`, id)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}

func (s *sqliteStore) GetByUsername(ctx context.Context, username string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+cols+` FROM users WHERE username = ? AND deleted_at IS NULL`, username)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by username: %w", err)
	}
	return u, nil
}

func (s *sqliteStore) GetByEmail(ctx context.Context, email string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+cols+` FROM users WHERE email = ? AND deleted_at IS NULL`, email)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

func (s *sqliteStore) List(ctx context.Context, f ListFilter) ([]*User, int, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	where := []string{"deleted_at IS NULL"}
	args := []any{}
	if f.Username != "" {
		where = append(where, "username LIKE ?")
		args = append(args, "%"+f.Username+"%")
	}
	if f.Email != "" {
		where = append(where, "email LIKE ?")
		args = append(args, "%"+f.Email+"%")
	}
	cond := " WHERE " + strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users"+cond, args...).
		Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}

	rows, err := s.db.QueryContext(ctx,
		"SELECT "+cols+" FROM users"+cond+" ORDER BY id LIMIT ? OFFSET ?",
		append(args, limit, f.Offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	out := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan user: %w", err)
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

func (s *sqliteStore) Update(ctx context.Context, u *User) error {
	u.UpdatedAt = time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET username = ?, email = ?, role = ?, updated_at = ?
		 WHERE id = ? AND deleted_at IS NULL`,
		u.Username, u.Email, u.Role, u.UpdatedAt, u.ID)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *sqliteStore) Delete(ctx context.Context, id int64) error {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`,
		now, now, id)
	if err != nil {
		return fmt.Errorf("soft-delete user: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// Close releases the underlying database handle.
func (s *sqliteStore) Close() error { return s.db.Close() }

// isUniqueViolation reports whether err is a UNIQUE constraint violation.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	// modernc.org/sqlite surfaces constraint failures through *sqlite.Error
	// with Code 19 (SQLITE_CONSTRAINT); extended codes 2067 (UNIQUE) and 1555
	// (PRIMARYKEY) are also possible. Fall back to a message match.
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() {
		case 19, 2067, 1555:
			return true
		}
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
