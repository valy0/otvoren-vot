package main

import "os"

// Config holds all environment-driven configuration for the tally service.
type Config struct {
	ListenAddr       string
	BulletinBoardURL string
	CeremonyAPIKey   string
	TrusteeKeysPath  string
	CeremonyStateDir string
	ElectionID       string
	TLSCertPath      string
	TLSKeyPath       string
	CACertPath       string
}

// LoadConfig reads configuration from environment variables with sensible
// defaults for local development.
func LoadConfig() *Config {
	return &Config{
		ListenAddr:       envOr("LISTEN_ADDR", ":8081"),
		BulletinBoardURL: envOr("BULLETIN_BOARD_URL", "http://localhost:8080"),
		CeremonyAPIKey:   os.Getenv("CEREMONY_API_KEY"),
		TrusteeKeysPath:  envOr("TRUSTEE_VERIFICATION_KEYS", ""),
		CeremonyStateDir: envOr("CEREMONY_STATE_DIR", "/var/lib/ceremony"),
		ElectionID:       os.Getenv("ELECTION_ID"),
		TLSCertPath:      envOr("TLS_CERT_PATH", ""),
		TLSKeyPath:       envOr("TLS_KEY_PATH", ""),
		CACertPath:       envOr("CA_CERT_PATH", ""),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
