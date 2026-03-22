package main

import (
	"os"
	"strings"
)

// Config holds the auth service configuration loaded from environment variables.
type Config struct {
	ListenAddr    string
	MockMode      bool
	RedisURL      string
	JWTPrivateKey string // file path to Ed25519 PEM
	ElectionID    string
	SessionAPIKey string
	TLSCertPath         string
	TLSKeyPath          string
	AllowedRedirectURIs []string
}

// LoadConfig reads configuration from the environment.
func LoadConfig() *Config {
	return &Config{
		ListenAddr:    envOr("LISTEN_ADDR", ":8082"),
		MockMode:      os.Getenv("EAUTH_MOCK") == "true",
		RedisURL:      envOr("REDIS_URL", "redis://localhost:6379"),
		JWTPrivateKey: envOr("AUTH_JWT_PRIVATE_KEY", ""),
		ElectionID:    envOr("ELECTION_ID", "00000000-0000-0000-0000-000000000000"),
		SessionAPIKey: envOr("SESSION_API_KEY", ""),
		TLSCertPath:         envOr("TLS_CERT_PATH", ""),
		TLSKeyPath:          envOr("TLS_KEY_PATH", ""),
		AllowedRedirectURIs: parseCSV(envOr("ALLOWED_REDIRECT_URIS", "http://localhost:*")),
	}
}

func parseCSV(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
