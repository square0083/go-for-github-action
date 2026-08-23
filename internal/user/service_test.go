package user

import (
	"context"
	"errors"
	"testing"
	"time"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	tm, err := NewTokenManager("test-secret", time.Hour)
	if err != nil {
		t.Fatalf("tm: %v", err)
	}
	return NewService(store, tm)
}

func adminClaims(id int64) *Claims { return &Claims{UserID: id, Role: RoleAdmin} }
func userClaims(id int64) *Claims  { return &Claims{UserID: id, Role: RoleUser} }

func TestCreateHashesPassword(t *testing.T) {
	svc := newTestService(t)
	u, err := svc.Create(context.Background(), CreateUserInput{
		Username: "alice", Email: "a@x.com", Password: "password123", Role: RoleUser,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.PasswordHash == "" || u.PasswordHash == "password123" {
		t.Fatal("password must be stored hashed, not plaintext")
	}
	if u.Role != RoleUser {
		t.Fatalf("role = %q", u.Role)
	}
	if u.ID == 0 {
		t.Fatal("created user should have an ID")
	}
}

func TestCreateRejectsDuplicateUsernameAndEmail(t *testing.T) {
	svc := newTestService(t)
	in := CreateUserInput{Username: "bob", Email: "b@x.com", Password: "password123", Role: RoleUser}
	if _, err := svc.Create(context.Background(), in); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := svc.Create(context.Background(), in); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate username want ErrConflict, got %v", err)
	}
	if _, err := svc.Create(context.Background(), CreateUserInput{
		Username: "carol", Email: "b@x.com", Password: "password123", Role: RoleUser,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate email want ErrConflict, got %v", err)
	}
}

func TestCreateValidatesInput(t *testing.T) {
	svc := newTestService(t)
	cases := []CreateUserInput{
		{Username: "ab", Email: "a@x.com", Password: "password123"},                   // username too short
		{Username: "alice", Email: "not-an-email", Password: "password123"},           // bad email
		{Username: "alice", Email: "a@x.com", Password: "short"},                      // password too short
		{Username: "alice", Email: "a@x.com", Password: "password123", Role: "super"}, // bad role
	}
	for i, in := range cases {
		if _, err := svc.Create(context.Background(), in); err == nil {
			t.Fatalf("case %d: expected validation error, got nil", i)
		}
	}
}

func TestAuthenticate(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_, err := svc.Create(ctx, CreateUserInput{Username: "dave", Email: "d@x.com", Password: "hunter22", Role: RoleUser})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	tok, u, err := svc.Authenticate(ctx, "dave", "hunter22")
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if tok == "" || u.Username != "dave" {
		t.Fatalf("unexpected auth result: tok=%q user=%v", tok, u)
	}
	if _, _, err := svc.Authenticate(ctx, "dave", "wrong"); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong password want ErrAuth, got %v", err)
	}
	if _, _, err := svc.Authenticate(ctx, "nobody", "hunter22"); !errors.Is(err, ErrAuth) {
		t.Fatalf("unknown user want ErrAuth, got %v", err)
	}
}

func TestPermissionAdminVsUser(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	admin, _ := svc.Create(ctx, CreateUserInput{Username: "root", Email: "r@x.com", Password: "password123", Role: RoleAdmin})
	alice, _ := svc.Create(ctx, CreateUserInput{Username: "alice", Email: "a@x.com", Password: "password123", Role: RoleUser})

	// Admin may view anyone.
	if _, err := svc.Get(ctx, adminClaims(admin.ID), alice.ID); err != nil {
		t.Fatalf("admin view other: %v", err)
	}
	// User may view self.
	if _, err := svc.Get(ctx, userClaims(alice.ID), alice.ID); err != nil {
		t.Fatalf("user view self: %v", err)
	}
	// User may not view another user.
	if _, err := svc.Get(ctx, userClaims(alice.ID), admin.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("user view other want ErrForbidden, got %v", err)
	}
}

func TestUpdateSelfElevationForbidden(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	alice, _ := svc.Create(ctx, CreateUserInput{Username: "alice", Email: "a@x.com", Password: "password123", Role: RoleUser})

	_, err := svc.Update(ctx, userClaims(alice.ID), alice.ID, UpdateUserInput{Role: RoleAdmin})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("self-elevation want ErrForbidden, got %v", err)
	}
}

func TestUpdateFields(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	u, _ := svc.Create(ctx, CreateUserInput{Username: "erin", Email: "e@x.com", Password: "password123", Role: RoleUser})

	updated, err := svc.Update(ctx, adminClaims(u.ID), u.ID, UpdateUserInput{Username: "erin2", Email: "e2@x.com"})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Username != "erin2" || updated.Email != "e2@x.com" || updated.Role != RoleUser {
		t.Fatalf("update not applied: %+v", updated)
	}
}

func TestDeleteSoftDelete(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	u, _ := svc.Create(ctx, CreateUserInput{Username: "frank", Email: "f@x.com", Password: "password123", Role: RoleUser})

	// Non-admin cannot delete.
	if err := svc.Delete(ctx, userClaims(u.ID), u.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("user delete want ErrForbidden, got %v", err)
	}
	// Admin deletes.
	if err := svc.Delete(ctx, adminClaims(u.ID), u.ID); err != nil {
		t.Fatalf("admin delete: %v", err)
	}
	// Soft-deleted user is no longer found.
	if _, err := svc.Get(ctx, adminClaims(u.ID), u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete want ErrNotFound, got %v", err)
	}
}

func TestListAdminPaginationAndFilter(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		name := string(rune('a' + i))
		_, err := svc.Create(ctx, CreateUserInput{
			Username: name + "user", Email: name + "@x.com", Password: "password123", Role: RoleUser,
		})
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	users, total, err := svc.List(ctx, adminClaims(0), ListFilter{Limit: 2, Offset: 0})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(users) != 2 || total != 5 {
		t.Fatalf("pagination: got %d users, total %d; want 2 and 5", len(users), total)
	}
	filtered, _, err := svc.List(ctx, adminClaims(0), ListFilter{Username: "cuser"})
	if err != nil || len(filtered) != 1 || filtered[0].Username != "cuser" {
		t.Fatalf("filter: %+v err=%v", filtered, err)
	}
}

func TestListUserOnlySeesSelf(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	alice, _ := svc.Create(ctx, CreateUserInput{Username: "alice", Email: "a@x.com", Password: "password123", Role: RoleUser})
	svc.Create(ctx, CreateUserInput{Username: "bob", Email: "b@x.com", Password: "password123", Role: RoleUser})

	users, total, err := svc.List(ctx, userClaims(alice.ID), ListFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 || len(users) != 1 || users[0].ID != alice.ID {
		t.Fatalf("user should only see self: users=%+v total=%d", users, total)
	}
}
