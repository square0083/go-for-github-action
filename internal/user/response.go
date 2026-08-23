package user

import (
	"encoding/json"
	"net/http"
)

// writeJSON marshals v as JSON with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Response already committed; nothing sensible to do.
		return
	}
}

// errorBody is the unified error shape: { "error": { "code", "message" } }.
type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// writeError renders a ServiceError as a unified error response.
func writeError(w http.ResponseWriter, e *ServiceError) {
	body := errorBody{}
	body.Error.Code = e.Code
	body.Error.Message = e.Message
	writeJSON(w, e.Status, body)
}

// writeInternal renders a generic 500 without leaking internals.
func writeInternal(w http.ResponseWriter) {
	writeError(w, NewServiceError(500, "internal", "internal server error"))
}
