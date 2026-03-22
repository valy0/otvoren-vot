package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/valy0/otvoren-vot/pkg/middleware"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg := LoadConfig()

	// --- Startup validation ---
	if cfg.CeremonyAPIKey == "" {
		slog.Error("CEREMONY_API_KEY is required")
		os.Exit(1)
	}
	if cfg.TrusteeKeysPath == "" {
		slog.Error("TRUSTEE_VERIFICATION_KEYS is required")
		os.Exit(1)
	}
	if cfg.ElectionID == "" {
		slog.Error("ELECTION_ID is required")
		os.Exit(1)
	}

	// --- Load trustee verification keys ---
	trusteeKeys, err := LoadTrusteeKeys(cfg.TrusteeKeysPath)
	if err != nil {
		slog.Error("failed to load trustee keys", "error", err)
		os.Exit(1)
	}
	slog.Info("loaded trustee keys", "count", len(trusteeKeys.Keys))

	// --- Create BB client ---
	bbClient := NewBBClient(cfg.BulletinBoardURL)

	// --- Create ceremony handler (includes crash recovery) ---
	handler, err := NewCeremonyHandler(bbClient, trusteeKeys, cfg.ElectionID, cfg.CeremonyStateDir)
	if err != nil {
		slog.Error("failed to initialize ceremony handler", "error", err)
		os.Exit(1)
	}

	// --- Wire routes ---
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	key := cfg.CeremonyAPIKey
	mux.HandleFunc("POST /api/v1/ceremony/start", middleware.RequireKey(key, handler.handleStart))
	mux.HandleFunc("GET /api/v1/ceremony/{id}", middleware.RequireKey(key, handler.handleStatus))
	mux.HandleFunc("POST /api/v1/ceremony/{id}/partial-decryption", middleware.RequireKey(key, handler.handlePartialDecryption))
	mux.HandleFunc("GET /api/v1/ceremony/{id}/results", handler.handleResults) // PUBLIC
	mux.HandleFunc("POST /api/v1/ceremony/{id}/finalize", middleware.RequireKey(key, handler.handleFinalize))

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 300 * time.Second, // Long timeout for ceremony operations
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		slog.Info("tally service shutting down")
		srv.Close()
	}()

	slog.Info("tally service listening", "addr", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
