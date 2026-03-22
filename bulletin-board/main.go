package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/valy0/otvoren-vot/bulletin-board/api"
	"github.com/valy0/otvoren-vot/bulletin-board/board"
	"github.com/valy0/otvoren-vot/bulletin-board/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg := LoadConfig()

	if cfg.InternalAPIKey == "" {
		slog.Error("INTERNAL_API_KEY environment variable must be set")
		os.Exit(1)
	}

	ctx := context.Background()

	// Connect to PostgreSQL
	s, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer s.Close()

	// Run migrations
	if err := s.RunMigrations(ctx); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}
	slog.Info("database migrations applied")

	// Create board
	b, err := board.New(ctx, s)
	if err != nil {
		slog.Error("failed to initialize board", "error", err)
		os.Exit(1)
	}
	slog.Info("board initialized", "existing_ballots", b.Size())

	// Create signer (dev key for now)
	signer := board.NewSigner(nil)
	slog.Info("root signer initialized (dev key)")

	// Start periodic root signing (every 60 seconds)
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			sr, err := signer.SignRoot(b)
			if err != nil {
				slog.Error("failed to sign root", "error", err)
				continue
			}
			if err := s.InsertSignedRoot(ctx, sr.ToStoreRecord()); err != nil {
				slog.Error("failed to store signed root", "error", err)
				continue
			}
			slog.Info("signed root", "root", sr.RootSHA256, "ballots", sr.BallotCount)
		}
	}()

	// Create HTTP router
	router := api.NewRouter(b, cfg.InternalAPIKey)

	// Create server
	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		slog.Info("bulletin board shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	slog.Info("bulletin board listening", "addr", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
	slog.Info("server stopped")
}
