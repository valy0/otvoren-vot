package main

import "os"

type Config struct {
	ListenAddr       string
	BulletinBoardURL string
	AuthServiceURL   string
	DatabaseURL      string
	ElectionID       string
	EGNHMACKey       string
}

func LoadConfig() *Config {
	return &Config{
		ListenAddr:       envOr("LISTEN_ADDR", ":8083"),
		BulletinBoardURL: envOr("BULLETIN_BOARD_URL", "http://localhost:8080"),
		AuthServiceURL:   envOr("AUTH_SERVICE_URL", "http://localhost:8082"),
		DatabaseURL:      envOr("DATABASE_URL", ""),
		ElectionID:       envOr("ELECTION_ID", "00000000-0000-0000-0000-000000000000"),
		EGNHMACKey:       envOr("EGN_HMAC_KEY", ""),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
