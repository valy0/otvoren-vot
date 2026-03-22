package main

import (
	"os"
	"strings"
)

type Config struct {
	ListenAddr         string
	BulletinBoardURL   string
	AuthServiceURL     string
	DatabaseURL        string
	ElectionID         string
	EGNHMACKey         string
	HistoryHMACKey     string
	OverrideReportDir  string
	DevAuth            bool
	AuthJWTPublicKey   string
	SessionAPIKey      string
	TLSCertPath        string
	TLSKeyPath         string
	CACertPath         string
	CORSAllowedOrigins []string
}

func LoadConfig() *Config {
	return &Config{
		ListenAddr:        envOr("LISTEN_ADDR", ":8083"),
		BulletinBoardURL:  envOr("BULLETIN_BOARD_URL", "http://localhost:8080"),
		AuthServiceURL:    envOr("AUTH_SERVICE_URL", "http://localhost:8082"),
		DatabaseURL:       envOr("DATABASE_URL", ""),
		ElectionID:        envOr("ELECTION_ID", "00000000-0000-0000-0000-000000000000"),
		EGNHMACKey:        envOr("EGN_HMAC_KEY", ""),
		HistoryHMACKey:    envOr("HISTORY_HMAC_KEY", ""),
		OverrideReportDir: envOr("OVERRIDE_REPORT_DIR", ""),
		DevAuth:           os.Getenv("COLLECTION_DEV_AUTH") == "true",
		AuthJWTPublicKey:  envOr("AUTH_JWT_PUBLIC_KEY", ""),
		SessionAPIKey:     envOr("SESSION_API_KEY", ""),
		TLSCertPath:       envOr("TLS_CERT_PATH", ""),
		TLSKeyPath:         envOr("TLS_KEY_PATH", ""),
		CACertPath:         envOr("CA_CERT_PATH", ""),
		CORSAllowedOrigins: parseCORSOrigins(envOr("CORS_ALLOWED_ORIGINS", "http://localhost:5173")),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseCORSOrigins(raw string) []string {
	var origins []string
	for _, o := range strings.Split(raw, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			origins = append(origins, o)
		}
	}
	return origins
}
