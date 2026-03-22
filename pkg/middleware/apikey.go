package middleware

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
)

// RequireKey returns middleware that validates the X-Internal-Key header.
func RequireKey(key string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Internal-Key")), []byte(key)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]string{
					"code":    "unauthorized",
					"message": "Invalid API key",
				},
			})
			return
		}
		next(w, r)
	}
}
