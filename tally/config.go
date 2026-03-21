package main

import "os"

type Config struct {
	ListenAddr       string
	BulletinBoardURL string
}

func LoadConfig() *Config {
	return &Config{
		ListenAddr:       envOr("LISTEN_ADDR", ":8081"),
		BulletinBoardURL: envOr("BULLETIN_BOARD_URL", "http://localhost:8080"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
