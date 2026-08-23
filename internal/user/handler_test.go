package user

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func newTestServer(t *testing.T) (*httptest.Server, *Service) {
	t.Helper()
	svc := newTestService(t)
	mux := http.NewServeMux()
	NewHandler(svc).Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, svc
}

func doJSON(t *testing.T, method, url, token string, body any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func login(t *testing.T, ts *httptest.Server, username, password string) string {
	t.Helper()
	code, body := doJSON(t, "POST", ts.URL+"/api/auth/login", "", map[string]any{
		"username": username, "password": password,
	})
	if code != http.StatusOK {
		t.Fatalf("login %s: status %d body %v", username, code, body)
	}
	return body["token"].(string)
}

func TestRegisterLoginAndProtectedAccess(t *testing.T) {
	ts, _ := newTestServer(t)

	// Register a user; password must not be returned.
	code, body := doJSON(t, "POST", ts.URL+"/api/auth/register", "", map[string]any{
		"username": "alice", "email": "a@x.com", "password": "password123",
	})
	if code != http.StatusCreated {
		t.Fatalf("register: status %d body %v", code, body)
	}
	if _, has := body["user"].(map[string]any)["password_hash"]; has {
		t.Fatal("password_hash must not be exposed in response")
	}

	// Login with valid credentials.
	tok := login(t, ts, "alice", "password123")

	// Authenticated access works.
	code, _ = doJSON(t, "GET", ts.URL+"/api/users", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("authenticated list: status %d", code)
	}

	// Unauthenticated request returns 401.
	code, body = doJSON(t, "GET", ts.URL+"/api/users", "", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated want 401, got %d body %v", code, body)
	}

	// Wrong password rejected with 401.
	code, _ = doJSON(t, "POST", ts.URL+"/api/auth/login", "", map[string]any{
		"username": "alice", "password": "wrongpass",
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong password want 401, got %d", code)
	}
}

func TestAdminFullCRUD(t *testing.T) {
	ts, svc := newTestServer(t)
	// Seed an admin directly via the service.
	admin, _ := svc.Create(context.Background(), CreateUserInput{
		Username: "root", Email: "r@x.com", Password: "password123", Role: RoleAdmin,
	})
	adminTok := login(t, ts, "root", "password123")

	// Admin creates a user with a chosen role.
	code, body := doJSON(t, "POST", ts.URL+"/api/users", adminTok, map[string]any{
		"username": "bob", "email": "b@x.com", "password": "password123", "role": "admin",
	})
	if code != http.StatusCreated {
		t.Fatalf("admin create: status %d body %v", code, body)
	}
	id := int64(body["user"].(map[string]any)["id"].(float64))

	// Admin updates.
	code, body = doJSON(t, "PUT", ts.URL+"/api/users/"+strconv.FormatInt(id, 10), adminTok, map[string]any{
		"email": "b2@x.com",
	})
	if code != http.StatusOK || body["user"].(map[string]any)["email"] != "b2@x.com" {
		t.Fatalf("admin update: status %d body %v", code, body)
	}

	// Admin deletes.
	req, _ := http.NewRequest("DELETE", ts.URL+"/api/users/"+strconv.FormatInt(id, 10), nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	dr, _ := http.DefaultClient.Do(req)
	dr.Body.Close()
	if dr.StatusCode != http.StatusNoContent {
		t.Fatalf("admin delete: status %d", dr.StatusCode)
	}
	_ = admin.ID
}

func TestUserCannotManageOthers(t *testing.T) {
	ts, svc := newTestServer(t)
	admin, _ := svc.Create(context.Background(), CreateUserInput{
		Username: "root", Email: "r@x.com", Password: "password123", Role: RoleAdmin,
	})
	alice, _ := svc.Create(context.Background(), CreateUserInput{
		Username: "alice", Email: "a@x.com", Password: "password123", Role: RoleUser,
	})
	aliceTok := login(t, ts, "alice", "password123")

	// User cannot view another user's record.
	code, _ := doJSON(t, "GET", ts.URL+"/api/users/"+strconv.FormatInt(admin.ID, 10), aliceTok, nil)
	if code != http.StatusForbidden {
		t.Fatalf("user view other want 403, got %d", code)
	}

	// User cannot create users (admin-only).
	code, _ = doJSON(t, "POST", ts.URL+"/api/users", aliceTok, map[string]any{
		"username": "mallory", "email": "m@x.com", "password": "password123", "role": "user",
	})
	if code != http.StatusForbidden {
		t.Fatalf("user create want 403, got %d", code)
	}

	// User cannot delete anyone.
	req, _ := http.NewRequest("DELETE", ts.URL+"/api/users/"+strconv.FormatInt(alice.ID, 10), nil)
	req.Header.Set("Authorization", "Bearer "+aliceTok)
	dr, _ := http.DefaultClient.Do(req)
	dr.Body.Close()
	if dr.StatusCode != http.StatusForbidden {
		t.Fatalf("user self-delete want 403, got %d", dr.StatusCode)
	}
}

func TestUnifiedErrorShape(t *testing.T) {
	ts, _ := newTestServer(t)
	code, body := doJSON(t, "GET", ts.URL+"/api/users/999999", "", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", code)
	}
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected unified error object, got %v", body)
	}
	if errObj["code"] != "unauthenticated" {
		t.Fatalf("unexpected error code %v", errObj["code"])
	}
}
