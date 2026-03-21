package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/valy0/otvoren-vot/auth/provider"
)

func main() {
	cfg := LoadConfig()

	var p provider.Provider
	if cfg.MockMode {
		p = provider.NewMockProvider()
		log.Println("Auth service running in MOCK mode")
	} else {
		log.Fatal("Production eAuth 2.0 provider not implemented yet")
	}

	mux := http.NewServeMux()
	mux.Handle("POST /authenticate", NewAuthHandler(p))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","provider":"` + p.Name() + `"}`))
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
		log.Println("Auth service shutting down...")
		srv.Close()
	}()

	log.Printf("Auth service listening on %s", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}
