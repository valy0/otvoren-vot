package main

import "os"

type Config struct {
	ListenAddr string
	MockMode   bool
}

func LoadConfig() *Config {
	return &Config{
		ListenAddr: envOr("LISTEN_ADDR", ":8082"),
		MockMode:   os.Getenv("EAUTH_MOCK") == "true", // explicit opt-in, not opt-out
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
