package main

import (
	"os"
)

type Config struct {
	DatabaseURL    string
	ListenAddr     string
	SigningKeyPath string
	InternalAPIKey string
}

func LoadConfig() *Config {
	return &Config{
		DatabaseURL:    envOr("DATABASE_URL", "postgres://board:dev@localhost:5432/bulletin_board?sslmode=disable"),
		ListenAddr:     envOr("LISTEN_ADDR", ":8080"),
		SigningKeyPath: envOr("SIGNING_KEY_PATH", ""),
		InternalAPIKey: envOr("INTERNAL_API_KEY", "dev-key"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
