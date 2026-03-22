package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/valy0/otvoren-vot/crypto/threshold"
	"github.com/valy0/otvoren-vot/pkg/middleware"
	"github.com/valy0/otvoren-vot/verification/session"
)

func main() {
	cfg := LoadConfig()

	// Validate configuration
	if !cfg.DevMode && cfg.VerificationAPIKey == "" {
		log.Fatal("VERIFICATION_API_KEY must be set in production mode")
	}
	if cfg.TrusteeThreshold < 1 || cfg.TrusteeTotal < cfg.TrusteeThreshold {
		log.Fatalf("Invalid threshold config: t=%d, n=%d", cfg.TrusteeThreshold, cfg.TrusteeTotal)
	}

	// Load parties from JSON file or fall back to env/default
	parties := loadParties(cfg.PartyListPath)
	if len(parties) == 0 {
		log.Fatal("No parties configured; set PARTY_LIST_PATH to a JSON file or provide defaults")
	}

	sessions := session.NewStore()
	sessions.StartCleanup(5 * time.Minute)

	handler := &VerificationHandler{
		sessions:  sessions,
		parties:   parties,
		threshold: cfg.TrusteeThreshold,
	}

	// Dev mode: run a local DKG to generate a dev secret
	if cfg.DevMode {
		log.Printf("DEV MODE: running local DKG (%d-of-%d) for development secret",
			cfg.TrusteeThreshold, cfg.TrusteeTotal)
		dealer := threshold.NewDealer(cfg.TrusteeThreshold, cfg.TrusteeTotal)
		handler.devSecret = dealer.Secret()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/session", handler.HandleCreateSession)
	mux.HandleFunc("POST /api/v1/verify", handler.HandleVerify)
	mux.HandleFunc("GET /health", handler.HandleHealth)

	// Internal endpoint protected by API key
	if cfg.VerificationAPIKey != "" {
		mux.HandleFunc("POST /internal/v1/shares",
			middleware.RequireKey(cfg.VerificationAPIKey, handler.HandleSubmitShare))
	} else if cfg.DevMode {
		// In dev mode without API key, expose unprotected for testing
		mux.HandleFunc("POST /internal/v1/shares", handler.HandleSubmitShare)
	}

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
		sessions.Stop()
		srv.Close()
	}()

	log.Printf("Verification service listening on %s (dev_mode=%v, threshold=%d-of-%d, parties=%d)",
		cfg.ListenAddr, cfg.DevMode, cfg.TrusteeThreshold, cfg.TrusteeTotal, len(parties))
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}

// loadParties reads a JSON array of party names from path, or returns a default list.
func loadParties(path string) []string {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("Failed to read party list from %s: %v", path, err)
		}
		var parties []string
		if err := json.Unmarshal(data, &parties); err != nil {
			log.Fatalf("Failed to parse party list from %s: %v", path, err)
		}
		return parties
	}

	// Fall back to PARTIES env or hardcoded default
	if env := os.Getenv("PARTIES"); env != "" {
		var parties []string
		if err := json.Unmarshal([]byte(env), &parties); err != nil {
			log.Fatalf("Failed to parse PARTIES env: %v", err)
		}
		return parties
	}

	return []string{"ГЕРБ", "ПП-ДБ", "ДПС", "БСП", "Възраждане"}
}
