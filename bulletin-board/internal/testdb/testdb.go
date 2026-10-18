// Package testdb holds the PostgreSQL connection rules shared by the
// bulletin-board tests.
package testdb

import (
	"os"
	"testing"
)

const defaultURL = "postgres://board:dev@localhost:5432/bulletin_board?sslmode=disable"

// URL returns TEST_DATABASE_URL, or the local development default.
func URL() string {
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		return url
	}
	return defaultURL
}

// Unavailable reports that PostgreSQL could not be reached. An explicitly
// configured database (TEST_DATABASE_URL set) that is unreachable is a
// failure; only the unconfigured local default may skip.
func Unavailable(t testing.TB, err error) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") != "" {
		t.Fatalf("TEST_DATABASE_URL is set but PostgreSQL is unreachable: %v", err)
	}
	t.Skipf("PostgreSQL not available: %v", err)
}
