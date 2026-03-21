package api

import (
	"net/http"

	"github.com/valy0/otvoren-vot/bulletin-board/board"
)

// NewRouter creates the HTTP handler with all routes.
func NewRouter(b *board.Board, internalAPIKey string) http.Handler {
	mux := http.NewServeMux()

	// Public read endpoints
	mux.HandleFunc("GET /api/v1/board", handleListBallots(b))
	mux.HandleFunc("GET /api/v1/board/root", handleGetRoot(b))
	mux.HandleFunc("GET /api/v1/board/{ballot_id}", handleGetBallot(b))
	mux.HandleFunc("GET /api/v1/election", handleGetElection())

	// Internal write endpoints
	mux.HandleFunc("POST /internal/v1/ballots", requireAPIKey(internalAPIKey, handleSubmitBallot(b)))

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	return withMiddleware(mux)
}

func requireAPIKey(key string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Key") != key {
			writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing API key")
			return
		}
		next(w, r)
	}
}
