package main

import (
	"context"
	"crypto/tls"
	"log/slog"
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
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg := LoadConfig()

	if cfg.JWTPrivateKey == "" {
		slog.Error("AUTH_JWT_PRIVATE_KEY must be set")
		os.Exit(1)
	}
	if cfg.SessionAPIKey == "" {
		slog.Error("SESSION_API_KEY must be set")
		os.Exit(1)
	}

	// Load JWT signing key.
	jwtPrivKey, err := jwtauth.LoadEd25519PrivateKey(cfg.JWTPrivateKey)
	if err != nil {
		slog.Error("failed to load JWT private key", "error", err)
		os.Exit(1)
	}

	// Connect to Redis.
	ctx := context.Background()
	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		slog.Error("invalid REDIS_URL", "error", err)
		os.Exit(1)
	}
	redisClient := redis.NewClient(opt)
	if err := redisClient.Ping(ctx).Err(); err != nil {
		slog.Error("redis not reachable", "error", err)
		os.Exit(1)
	}
	defer redisClient.Close()

	// Create session store and rate limiter.
	sessions := session.NewRedisStore(redisClient)
	rateLimiter := session.NewRateLimiter(redisClient)

	// Select auth provider.
	var p provider.Provider
	if cfg.MockMode {
		p = provider.NewMockProvider()
		slog.Warn("auth service running in MOCK mode")
	} else {
		slog.Error("production eAuth 2.0 provider not implemented yet")
		os.Exit(1)
	}

	authHandler := NewAuthHandler(p, sessions, rateLimiter, jwtPrivKey, cfg.ElectionID)
	loginHandler := NewLoginHandler(p, sessions, rateLimiter, jwtPrivKey, cfg.ElectionID, cfg.AllowedRedirectURIs)

	mux := http.NewServeMux()
	mux.Handle("POST /authenticate", authHandler)
	mux.HandleFunc("GET /internal/v1/session/{id}", middleware.RequireKey(cfg.SessionAPIKey, authHandler.HandleResolveSession))
	mux.HandleFunc("GET /login", loginHandler.HandleGetLogin)
	mux.HandleFunc("POST /login", loginHandler.HandlePostLogin)
	mux.HandleFunc("GET /session/status", loginHandler.HandleSessionStatus)
	mux.HandleFunc("OPTIONS /session/status", loginHandler.HandleSessionStatusOptions)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","provider":"` + p.Name() + `"}`))
	})

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS12},
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		slog.Info("auth service shutting down")
		srv.Close()
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
}
