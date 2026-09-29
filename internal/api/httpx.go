// Package api — REST v1 helpers (PRD R10): JSON, /api/v1, cursor pagination,
// structured error bodies {code, message, details}.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/blawesom/partout/internal/store"
)

// ---- structured errors -----------------------------------------------------

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// writeError sends a structured error body.
func writeError(w http.ResponseWriter, status int, code, message string, details any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(apiError{Code: code, Message: message, Details: details})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// maxJSONBody bounds every JSON request body. The largest legitimate one
// is a release artifact upload (100 MiB artifact ~ 134 MiB base64 in JSON);
// 256 MiB leaves headroom while capping memory from a runaway client.
const maxJSONBody = 256 << 20

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if _, ok := err.(*http.MaxBytesError); ok {
			return fmt.Errorf("request body too large (max %d MiB)", maxJSONBody>>20)
		}
		return err
	}
	return nil
}

// ---- helpers -----------------------------------------------------------------

// isNotFound reports whether err is a store not-found.
func isNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }

// queryInt returns the query param as an int with a default.
func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// pageParams reads ?limit= and ?cursor= query parameters.
func pageParams(r *http.Request, defaultLimit int) (limit int, cursor string) {
	limit = defaultLimit
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 500 {
		limit = 500
	}
	cursor = r.URL.Query().Get("cursor")
	return
}

// hasMore reports whether more pages exist (len == requested limit).
func hasMore(limit, n int) bool { return n == limit }
