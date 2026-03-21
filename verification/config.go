package main

import "os"

type Config struct {
	ListenAddr string
}

func LoadConfig() *Config {
	return &Config{
		ListenAddr: envOr("LISTEN_ADDR", ":8084"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
