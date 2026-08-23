package user

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// contextKey is an unexported key type to avoid collisions.
type contextKey int

const claimsKey contextKey = 0

// ctxWithClaims stores parsed claims in a request context.
func ctxWithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, c)
}

// claimsFrom returns the authenticated claims or nil.
func claimsFrom(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsKey).(*Claims)
	return c
}

// Handler exposes the user API over HTTP.
type Handler struct {
	svc *Service
}

// NewHandler builds an HTTP handler for the user service.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Register mounts the user routes onto mux. Go 1.21 compatible: no method
// patterns or path wildcards; dispatch happens inside the handlers.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/auth/register", h.routeRegister)
	mux.HandleFunc("/api/auth/login", h.routeLogin)
	mux.HandleFunc("/api/users", h.routeUsers)
	mux.HandleFunc("/api/users/", h.routeUserByID)
}

// requireAuth guards a handler behind a valid Bearer token.
func (h *Handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := bearerToken(r)
		if !ok {
			writeError(w, ErrUnauthenticated)
			return
		}
		claims, err := h.svc.tm.Parse(tok)
		if err != nil {
			writeError(w, ErrUnauthenticated)
			return
		}
		next(w, r.WithContext(ctxWithClaims(r.Context(), claims)))
	}
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	return tok, tok != ""
}

func (h *Handler) routeRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, NewServiceError(405, "method_not_allowed", "method not allowed"))
		return
	}
	h.handleRegister(w, r)
}

func (h *Handler) routeLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, NewServiceError(405, "method_not_allowed", "method not allowed"))
		return
	}
	h.handleLogin(w, r)
}

// routeUsers dispatches the collection endpoints: GET list, POST create.
func (h *Handler) routeUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.requireAuth(h.handleList)(w, r)
	case http.MethodPost:
		h.requireAuth(h.handleCreate)(w, r)
	default:
		writeError(w, NewServiceError(405, "method_not_allowed", "method not allowed"))
	}
}

// routeUserByID dispatches the per-resource endpoints: GET, PUT, DELETE.
func (h *Handler) routeUserByID(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.requireAuth(h.handleGet)(w, r)
	case http.MethodPut:
		h.requireAuth(h.handleUpdate)(w, r)
	case http.MethodDelete:
		h.requireAuth(h.handleDelete)(w, r)
	default:
		writeError(w, NewServiceError(405, "method_not_allowed", "method not allowed"))
	}
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	var in CreateUserInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, NewServiceError(400, "invalid_input", err.Error()))
		return
	}
	// Registration always creates a standard user; role assignment is
	// reserved for admins via POST /api/users.
	in.Role = RoleUser
	u, err := h.svc.Create(r.Context(), in)
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": u.Sanitized()})
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, NewServiceError(400, "invalid_input", err.Error()))
		return
	}
	tok, u, err := h.svc.Authenticate(r.Context(), in.Username, in.Password)
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": tok,
		"user":  u.Sanitized(),
	})
}

func (h *Handler) handleCreate(w http.ResponseWriter, r *http.Request) {
	actor := claimsFrom(r.Context())
	if actor.Role != RoleAdmin {
		writeError(w, ErrForbidden)
		return
	}
	var in CreateUserInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, NewServiceError(400, "invalid_input", err.Error()))
		return
	}
	u, err := h.svc.Create(r.Context(), in)
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": u.Sanitized()})
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	actor := claimsFrom(r.Context())
	f := ListFilter{
		Username: r.URL.Query().Get("username"),
		Email:    r.URL.Query().Get("email"),
	}
	f.Limit = atoiDefault(r.URL.Query().Get("limit"), 10)
	f.Offset = atoiDefault(r.URL.Query().Get("offset"), 0)
	users, total, err := h.svc.List(r.Context(), actor, f)
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	sanitized := make([]*User, 0, len(users))
	for _, u := range users {
		sanitized = append(sanitized, u.Sanitized())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"users":  sanitized,
		"total":  total,
		"limit":  f.Limit,
		"offset": f.Offset,
	})
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	actor := claimsFrom(r.Context())
	id, err := pathID(r)
	if err != nil {
		writeError(w, NewServiceError(400, "invalid_input", err.Error()))
		return
	}
	u, err := h.svc.Get(r.Context(), actor, id)
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": u.Sanitized()})
}

func (h *Handler) handleUpdate(w http.ResponseWriter, r *http.Request) {
	actor := claimsFrom(r.Context())
	id, err := pathID(r)
	if err != nil {
		writeError(w, NewServiceError(400, "invalid_input", err.Error()))
		return
	}
	var in UpdateUserInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, NewServiceError(400, "invalid_input", err.Error()))
		return
	}
	u, err := h.svc.Update(r.Context(), actor, id, in)
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": u.Sanitized()})
}

func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request) {
	actor := claimsFrom(r.Context())
	id, err := pathID(r)
	if err != nil {
		writeError(w, NewServiceError(400, "invalid_input", err.Error()))
		return
	}
	if err := h.svc.Delete(r.Context(), actor, id); err != nil {
		writeServiceErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// pathID extracts the trailing id segment from /api/users/{id}.
func pathID(r *http.Request) (int64, error) {
	const prefix = "/api/users/"
	p := r.URL.Path
	if !strings.HasPrefix(p, prefix) {
		return 0, errors.New("invalid user path")
	}
	raw := strings.TrimSuffix(p[len(prefix):], "/")
	if raw == "" {
		return 0, errors.New("invalid user id")
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid user id")
	}
	return id, nil
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return def
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeServiceErr(w http.ResponseWriter, err error) {
	var se *ServiceError
	if errors.As(err, &se) {
		writeError(w, se)
		return
	}
	writeInternal(w)
}
