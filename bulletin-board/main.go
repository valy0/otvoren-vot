package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
	s, err := store.New(ctx, cfg.DatabaseURL, cfg.DBMaxConns, cfg.DBMinConns)
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

	// Create signer
	var signer *board.Signer
	if cfg.SigningKeyPath != "" {
		key, err := loadECDSAKey(cfg.SigningKeyPath)
		if err != nil {
			slog.Error("failed to load signing key", "error", err)
			os.Exit(1)
		}
		signer = board.NewSigner(key)
		slog.Info("root signer initialized from key file", "path", cfg.SigningKeyPath)
	} else {
		signer = board.NewSigner(nil)
		slog.Warn("root signer using ephemeral dev key — NOT FOR PRODUCTION")
	}

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

	// Parse allowed CORS origins
	origins := strings.Split(cfg.AllowedOrigins, ",")
	for i, o := range origins {
		origins[i] = strings.TrimSpace(o)
	}

	// Create HTTP router
	router := api.NewRouter(b, cfg.InternalAPIKey, origins, cfg.ElectionID)

	// Create server
	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS12},
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

	var listenErr error
	if cfg.TLSCertPath != "" && cfg.TLSKeyPath != "" {
		slog.Info("starting HTTPS server", "addr", cfg.ListenAddr)
		listenErr = srv.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath)
	} else {
		slog.Warn("starting HTTP server (no TLS configured)", "addr", cfg.ListenAddr)
		listenErr = srv.ListenAndServe()
	}
	if listenErr != nil && listenErr != http.ErrServerClosed {
		slog.Error("server error", "error", listenErr)
		os.Exit(1)
	}
	slog.Info("server stopped")
}

// loadECDSAKey reads a PEM-encoded ECDSA P-256 private key from a file.
func loadECDSAKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC private key: %w", err)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("expected P-256 curve, got %s", key.Curve.Params().Name)
	}
	return key, nil
}
