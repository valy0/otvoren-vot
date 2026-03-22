package main

import (
	"encoding/json"
	"log/slog"
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
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg := LoadConfig()

	// Validate configuration
	if !cfg.DevMode && cfg.VerificationAPIKey == "" {
		slog.Error("VERIFICATION_API_KEY must be set in production mode")
		os.Exit(1)
	}
	if cfg.TrusteeThreshold < 1 || cfg.TrusteeTotal < cfg.TrusteeThreshold {
		slog.Error("invalid threshold config", "t", cfg.TrusteeThreshold, "n", cfg.TrusteeTotal)
		os.Exit(1)
	}

	// Load parties from JSON file or fall back to env/default
	parties := loadParties(cfg.PartyListPath)
	if len(parties) == 0 {
		slog.Error("no parties configured; set PARTY_LIST_PATH to a JSON file or provide defaults")
		os.Exit(1)
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
		slog.Warn("dev mode: running local DKG for development secret",
			"threshold", cfg.TrusteeThreshold, "total", cfg.TrusteeTotal)
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
		slog.Info("verification service shutting down")
		sessions.Stop()
		srv.Close()
	}()

	slog.Info("verification service listening",
		"addr", cfg.ListenAddr, "dev_mode", cfg.DevMode,
		"threshold", cfg.TrusteeThreshold, "total", cfg.TrusteeTotal,
		"parties", len(parties))
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

// loadParties reads a JSON array of party names from path, or returns a default list.
func loadParties(path string) []string {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Error("failed to read party list", "path", path, "error", err)
			os.Exit(1)
		}
		var parties []string
		if err := json.Unmarshal(data, &parties); err != nil {
			slog.Error("failed to parse party list", "path", path, "error", err)
			os.Exit(1)
		}
		return parties
	}

	// Fall back to PARTIES env or hardcoded default
	if env := os.Getenv("PARTIES"); env != "" {
		var parties []string
		if err := json.Unmarshal([]byte(env), &parties); err != nil {
			slog.Error("failed to parse PARTIES env", "error", err)
			os.Exit(1)
		}
		return parties
	}

	return []string{"ГЕРБ", "ПП-ДБ", "ДПС", "БСП", "Възраждане"}
}
