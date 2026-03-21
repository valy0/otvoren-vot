package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/valy0/otvoren-vot/collection/votermap"
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

	vm := votermap.New()
	handler := NewCollectionHandler(vm, cfg.BulletinBoardURL, apiKey, activeSetKey)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/submit", handler.HandleSubmit)
	mux.HandleFunc("GET /internal/v1/active-set", requireKey(activeSetKey, handler.HandleActiveSet))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","voters":` + fmt.Sprintf("%d", vm.Size()) + `}`))
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
