package main

import "os"

type Config struct {
	StationID     string
	CollectionURL string
	NumParties    int
	DataDir       string
}

func LoadConfig() *Config {
	numParties := 8 // default for test elections
	return &Config{
		StationID:     envOr("STATION_ID", "station-001"),
		CollectionURL: envOr("COLLECTION_URL", "http://localhost:8083"),
		NumParties:    numParties,
		DataDir:       envOr("DATA_DIR", "./data"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
