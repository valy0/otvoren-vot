package main

import (
	"context"
	"log"
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
	cfg := LoadConfig()
	ctx := context.Background()

	// Connect to PostgreSQL
	s, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer s.Close()

	// Run migrations
	if err := s.RunMigrations(ctx); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}
	log.Println("Database migrations applied")

	// Create board
	b, err := board.New(ctx, s)
	if err != nil {
		log.Fatalf("Failed to initialize board: %v", err)
	}
	log.Printf("Board initialized with %d existing ballots", b.Size())

	// Create signer (dev key for now)
	signer := board.NewSigner(nil)
	log.Println("Root signer initialized (dev key)")

	// Start periodic root signing (every 60 seconds)
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			sr, err := signer.SignRoot(b)
			if err != nil {
				log.Printf("Failed to sign root: %v", err)
				continue
			}
			if err := s.InsertSignedRoot(ctx, sr.ToStoreRecord()); err != nil {
				log.Printf("Failed to store signed root: %v", err)
				continue
			}
			log.Printf("Signed root: %s (ballots: %d)", sr.RootSHA256, sr.BallotCount)
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
		log.Println("Shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	log.Printf("Bulletin Board listening on %s", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
	log.Println("Server stopped")
}
