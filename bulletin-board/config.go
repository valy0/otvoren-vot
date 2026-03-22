package main

import (
	"os"
)

type Config struct {
	DatabaseURL    string
	ListenAddr     string
	SigningKeyPath string
	InternalAPIKey string
	DBMaxConns     int32
	DBMinConns     int32
	AllowedOrigins string
	TLSCertPath    string
	TLSKeyPath     string
}

func LoadConfig() *Config {
	return &Config{
		DatabaseURL:    envOr("DATABASE_URL", "postgres://board:dev@localhost:5432/bulletin_board?sslmode=disable"),
		ListenAddr:     envOr("LISTEN_ADDR", ":8080"),
		SigningKeyPath: envOr("SIGNING_KEY_PATH", ""),
		InternalAPIKey: os.Getenv("INTERNAL_API_KEY"), // no fallback — must be set explicitly
		DBMaxConns:     int32(envIntOr("DB_MAX_CONNS", 25)),
		DBMinConns:     int32(envIntOr("DB_MIN_CONNS", 5)),
		AllowedOrigins: envOr("ALLOWED_ORIGINS", "*"),
		TLSCertPath:    envOr("TLS_CERT_PATH", ""),
		TLSKeyPath:     envOr("TLS_KEY_PATH", ""),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return fallback
		}
		n = n*10 + int(c-'0')
	}
	return n
}
