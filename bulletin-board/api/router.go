package api

import (
	"crypto/subtle"
	"net/http"

	"github.com/valy0/otvoren-vot/bulletin-board/board"
)

// NewRouter creates the HTTP handler with all routes.
func NewRouter(b *board.Board, internalAPIKey string, allowedOrigins []string) http.Handler {
	mux := http.NewServeMux()

	// Public read endpoints (with CORS)
	publicMux := http.NewServeMux()
	publicMux.HandleFunc("GET /api/v1/board", handleListBallots(b))
	publicMux.HandleFunc("GET /api/v1/board/root", handleGetRoot(b))
	publicMux.HandleFunc("GET /api/v1/board/{ballot_id}", handleGetBallot(b))
	publicMux.HandleFunc("GET /api/v1/election", handleGetElection())
	publicMux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Internal write endpoints (no CORS)
	internalMux := http.NewServeMux()
	internalMux.HandleFunc("POST /internal/v1/ballots", requireAPIKey(internalAPIKey, handleSubmitBallot(b)))

	// Combine: public gets CORS + logging, internal gets logging only
	cors := withCORS(allowedOrigins)
	mux.Handle("/api/", cors(withLogging(publicMux)))
	mux.Handle("/health", cors(withLogging(publicMux)))
	mux.Handle("/internal/", withLogging(internalMux))

	return mux
}

func requireAPIKey(key string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provided := r.Header.Get("X-Internal-Key")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(key)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing API key")
			return
		}
		next(w, r)
	}
}
