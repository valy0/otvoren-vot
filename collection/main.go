package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/valy0/otvoren-vot/collection/store"
	"github.com/valy0/otvoren-vot/collection/votermap"
	"github.com/valy0/otvoren-vot/pkg/jwtauth"
	"github.com/valy0/otvoren-vot/pkg/middleware"
)

func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool)
	for _, o := range allowedOrigins {
		allowed[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if allowed[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Vary", "Origin")
			}
			if r.Method == "OPTIONS" {
				w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.Header().Set("Access-Control-Max-Age", "86400")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg := LoadConfig()

	apiKey := os.Getenv("BULLETIN_BOARD_API_KEY")
	if apiKey == "" {
		slog.Error("BULLETIN_BOARD_API_KEY environment variable must be set")
		os.Exit(1)
	}

	activeSetKey := os.Getenv("ACTIVE_SET_API_KEY")
	if activeSetKey == "" {
		slog.Error("ACTIVE_SET_API_KEY environment variable must be set")
		os.Exit(1)
	}

	// Dev auth safety: prevent enabling dev auth when a real database is configured.
	if cfg.DevAuth && cfg.DatabaseURL != "" {
		slog.Error("COLLECTION_DEV_AUTH cannot be true when DATABASE_URL is set (production safety)")
		os.Exit(1)
	}
	if !cfg.DevAuth && cfg.AuthJWTPublicKey == "" {
		slog.Error("AUTH_JWT_PUBLIC_KEY must be set when dev auth is disabled")
		os.Exit(1)
	}
	if !cfg.DevAuth && cfg.SessionAPIKey == "" {
		slog.Error("SESSION_API_KEY must be set when dev auth is disabled")
		os.Exit(1)
	}
	if cfg.DevAuth {
		slog.Warn("dev auth enabled, X-Voter-EGN header accepted without JWT")
	}

	// Load JWT public key (production mode only).
	var jwtPubKey ed25519.PublicKey
	if !cfg.DevAuth {
		var err error
		jwtPubKey, err = jwtauth.LoadEd25519PublicKey(cfg.AuthJWTPublicKey)
		if err != nil {
			slog.Error("failed to load JWT public key", "error", err)
			os.Exit(1)
		}
	}

	ctx := context.Background()

	egnHMACKey := []byte(cfg.EGNHMACKey)
	if cfg.DatabaseURL != "" && cfg.EGNHMACKey == "" {
		slog.Error("EGN_HMAC_KEY must be set when using PostgreSQL (required to protect voter identity hashes)")
		os.Exit(1)
	}
	if cfg.EGNHMACKey == "" {
		slog.Warn("no EGN_HMAC_KEY set, using empty key (development only)")
	}

	if cfg.DatabaseURL != "" && cfg.HistoryHMACKey == "" {
		slog.Error("HISTORY_HMAC_KEY must be set when using PostgreSQL (required for vote history integrity)")
		os.Exit(1)
	}

	var voterStore votermap.Store
	if cfg.DatabaseURL != "" {
		pgStore, err := store.New(ctx, cfg.DatabaseURL, cfg.ElectionID, []byte(cfg.HistoryHMACKey))
		if err != nil {
			slog.Error("failed to connect to database", "error", err)
			os.Exit(1)
		}
		if err := pgStore.RunMigrations(ctx); err != nil {
			slog.Error("failed to run migrations", "error", err)
			os.Exit(1)
		}
		defer pgStore.Close()
		voterStore = pgStore
		slog.Info("using PostgreSQL store", "election_id", cfg.ElectionID)
	} else {
		slog.Warn("no DATABASE_URL set, using in-memory store (data will not persist across restarts)")
		voterStore = votermap.NewMemoryStore([]byte(cfg.HistoryHMACKey))
	}

	httpClient := &http.Client{Timeout: 3 * time.Second}
	if cfg.CACertPath != "" {
		caCert, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			log.Fatalf("failed to read CA cert: %v", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			log.Fatal("failed to parse CA cert")
		}
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		}
	}

	handler := NewCollectionHandler(
		voterStore, egnHMACKey, cfg.BulletinBoardURL, apiKey, activeSetKey, cfg.OverrideReportDir,
		cfg.DevAuth, jwtPubKey, cfg.AuthServiceURL, cfg.SessionAPIKey, cfg.ElectionID,
		httpClient,
	)

	cors := corsMiddleware(cfg.CORSAllowedOrigins)

	mux := http.NewServeMux()
	mux.Handle("/api/v1/submit", cors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.Header().Set("Allow", "POST")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		handler.HandleSubmit(w, r)
	})))
	mux.HandleFunc("GET /internal/v1/active-set", middleware.RequireKey(activeSetKey, handler.HandleActiveSet))
	mux.HandleFunc("GET /internal/v1/override-report", middleware.RequireKey(activeSetKey, handler.HandleOverrideReport))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS12},
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		slog.Info("collection server shutting down")
		srv.Close()
	}()

	var listenErr error
	if cfg.TLSCertPath != "" && cfg.TLSKeyPath != "" {
		slog.Info("starting HTTPS server", "addr", cfg.ListenAddr, "bulletin_board", cfg.BulletinBoardURL)
		listenErr = srv.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath)
	} else {
		slog.Warn("starting HTTP server (no TLS configured)", "addr", cfg.ListenAddr, "bulletin_board", cfg.BulletinBoardURL)
		listenErr = srv.ListenAndServe()
	}
	if listenErr != nil && listenErr != http.ErrServerClosed {
		slog.Error("server error", "error", listenErr)
		os.Exit(1)
	}
}
