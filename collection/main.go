package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
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

func main() {
	cfg := LoadConfig()

	apiKey := os.Getenv("BULLETIN_BOARD_API_KEY")
	if apiKey == "" {
		log.Fatal("BULLETIN_BOARD_API_KEY environment variable must be set")
	}

	activeSetKey := os.Getenv("ACTIVE_SET_API_KEY")
	if activeSetKey == "" {
		log.Fatal("ACTIVE_SET_API_KEY environment variable must be set")
	}

	// Dev auth safety: prevent enabling dev auth when a real database is configured.
	if cfg.DevAuth && cfg.DatabaseURL != "" {
		log.Fatal("COLLECTION_DEV_AUTH cannot be true when DATABASE_URL is set (production safety)")
	}
	if !cfg.DevAuth && cfg.AuthJWTPublicKey == "" {
		log.Fatal("AUTH_JWT_PUBLIC_KEY must be set when dev auth is disabled")
	}
	if !cfg.DevAuth && cfg.SessionAPIKey == "" {
		log.Fatal("SESSION_API_KEY must be set when dev auth is disabled")
	}
	if cfg.DevAuth {
		log.Println("WARNING: Dev auth enabled — X-Voter-EGN header accepted without JWT")
	}

	// Load JWT public key (production mode only).
	var jwtPubKey ed25519.PublicKey
	if !cfg.DevAuth {
		var err error
		jwtPubKey, err = jwtauth.LoadEd25519PublicKey(cfg.AuthJWTPublicKey)
		if err != nil {
			log.Fatalf("Failed to load JWT public key: %v", err)
		}
	}

	ctx := context.Background()

	egnHMACKey := []byte(cfg.EGNHMACKey)
	if cfg.DatabaseURL != "" && cfg.EGNHMACKey == "" {
		log.Fatal("EGN_HMAC_KEY must be set when using PostgreSQL (required to protect voter identity hashes)")
	}
	if cfg.EGNHMACKey == "" {
		log.Println("WARNING: No EGN_HMAC_KEY set, using empty key (development only)")
	}

	if cfg.DatabaseURL != "" && cfg.HistoryHMACKey == "" {
		log.Fatal("HISTORY_HMAC_KEY must be set when using PostgreSQL (required for vote history integrity)")
	}

	var voterStore votermap.Store
	if cfg.DatabaseURL != "" {
		pgStore, err := store.New(ctx, cfg.DatabaseURL, cfg.ElectionID, []byte(cfg.HistoryHMACKey))
		if err != nil {
			log.Fatalf("Failed to connect to database: %v", err)
		}
		if err := pgStore.RunMigrations(ctx); err != nil {
			log.Fatalf("Failed to run migrations: %v", err)
		}
		defer pgStore.Close()
		voterStore = pgStore
		log.Printf("Using PostgreSQL store (election %s)", cfg.ElectionID)
	} else {
		log.Println("WARNING: No DATABASE_URL set, using in-memory store (data will not persist across restarts)")
		voterStore = votermap.NewMemoryStore([]byte(cfg.HistoryHMACKey))
	}

	httpClient := &http.Client{Timeout: 3 * time.Second}

	handler := NewCollectionHandler(
		voterStore, egnHMACKey, cfg.BulletinBoardURL, apiKey, activeSetKey, cfg.OverrideReportDir,
		cfg.DevAuth, jwtPubKey, cfg.AuthServiceURL, cfg.SessionAPIKey, cfg.ElectionID,
		httpClient,
	)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/submit", handler.HandleSubmit)
	mux.HandleFunc("GET /internal/v1/active-set", middleware.RequireKey(activeSetKey, handler.HandleActiveSet))
	mux.HandleFunc("GET /internal/v1/override-report", middleware.RequireKey(activeSetKey, handler.HandleOverrideReport))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		size, err := voterStore.Size(r.Context())
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"status":"error"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"status":"ok","voters":%d}`, size)))
	})

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Collection server shutting down...")
		srv.Close()
	}()

	log.Printf("Collection server listening on %s", cfg.ListenAddr)
	log.Printf("Bulletin board: %s", cfg.BulletinBoardURL)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}
