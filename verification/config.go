package main

import "os"

// Config holds the verification service configuration.
type Config struct {
	ListenAddr         string
	DevMode            bool
	VerificationAPIKey string
	PartyListPath      string
	TrusteeThreshold   int
	TrusteeTotal       int
	TLSCertPath        string
	TLSKeyPath         string
}

// LoadConfig reads configuration from environment variables.
func LoadConfig() *Config {
	return &Config{
		ListenAddr:         envOr("LISTEN_ADDR", ":8084"),
		DevMode:            os.Getenv("DEV_MODE") == "true",
		VerificationAPIKey: os.Getenv("VERIFICATION_API_KEY"),
		PartyListPath:      os.Getenv("PARTY_LIST_PATH"),
		TrusteeThreshold:   envIntOr("TRUSTEE_THRESHOLD", 3),
		TrusteeTotal:       envIntOr("TRUSTEE_TOTAL", 5),
		TLSCertPath:        envOr("TLS_CERT_PATH", ""),
		TLSKeyPath:         envOr("TLS_KEY_PATH", ""),
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
