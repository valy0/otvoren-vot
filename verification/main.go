package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/valy0/otvoren-vot/verification/codes"
	"github.com/valy0/otvoren-vot/verification/session"
)

func main() {
	cfg := LoadConfig()

	sessions := session.NewStore()
	// In production, this secret is threshold-distributed among verification trustees
	secretStr := os.Getenv("VERIFICATION_SECRET")
	if secretStr == "" {
		log.Fatal("VERIFICATION_SECRET environment variable must be set")
	}
	verificationSecret := []byte(secretStr)
	parties := []string{"ГЕРБ", "ПП-ДБ", "ДПС", "БСП", "Възраждане"}

	mux := http.NewServeMux()

	// Create a new verification session (called by extension after page load)
	mux.HandleFunc("POST /api/v1/session", func(w http.ResponseWriter, r *http.Request) {
		sess, err := sessions.Create()
		if err != nil {
			http.Error(w, "failed to create session", 500)
			return
		}
		mapping := codes.GenerateCodeMapping(sess.ID, parties, verificationSecret)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"session_id":   sess.ID,
			"code_mapping": mapping.Codes,
		})
	})

	// Get return code for a submitted ballot (called by extension after submission)
	mux.HandleFunc("POST /api/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SessionID       string          `json:"session_id"`
			EncryptedBallot json.RawMessage `json:"encrypted_ballot"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", 400)
			return
		}

		sess, ok := sessions.Get(req.SessionID)
		if !ok {
			http.Error(w, "invalid session", 404)
			return
		}
		if sess.Verified {
			http.Error(w, "session already verified", 409)
			return
		}

		returnCode := codes.DeriveReturnCode(verificationSecret, req.SessionID, req.EncryptedBallot)
		sessions.MarkVerified(req.SessionID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"return_code": returnCode,
		})
	})

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "ok",
			"sessions": sessions.Count(),
		})
	})

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Verification service shutting down...")
		srv.Close()
	}()

	log.Printf("Verification service listening on %s", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}
