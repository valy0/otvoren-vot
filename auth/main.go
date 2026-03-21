package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/valy0/otvoren-vot/auth/provider"
	"github.com/valy0/otvoren-vot/auth/session"
	"github.com/valy0/otvoren-vot/pkg/jwtauth"
	"github.com/valy0/otvoren-vot/pkg/middleware"
)

func main() {
	cfg := LoadConfig()

	if cfg.JWTPrivateKey == "" {
		log.Fatal("AUTH_JWT_PRIVATE_KEY must be set")
	}
	if cfg.SessionAPIKey == "" {
		log.Fatal("SESSION_API_KEY must be set")
	}

	// Load JWT signing key.
	jwtPrivKey, err := jwtauth.LoadEd25519PrivateKey(cfg.JWTPrivateKey)
	if err != nil {
		log.Fatalf("Failed to load JWT private key: %v", err)
	}

	// Connect to Redis.
	ctx := context.Background()
	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Fatalf("Invalid REDIS_URL: %v", err)
	}
	redisClient := redis.NewClient(opt)
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("Redis not reachable: %v", err)
	}
	defer redisClient.Close()

	// Create session store and rate limiter.
	sessions := session.NewRedisStore(redisClient)
	rateLimiter := session.NewRateLimiter(redisClient)

	// Select auth provider.
	var p provider.Provider
	if cfg.MockMode {
		p = provider.NewMockProvider()
		log.Println("Auth service running in MOCK mode")
	} else {
		log.Fatal("Production eAuth 2.0 provider not implemented yet")
	}

	authHandler := NewAuthHandler(p, sessions, rateLimiter, jwtPrivKey, cfg.ElectionID)

	mux := http.NewServeMux()
	mux.Handle("POST /authenticate", authHandler)
	mux.HandleFunc("GET /internal/v1/session/{id}", middleware.RequireKey(cfg.SessionAPIKey, authHandler.HandleResolveSession))
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
