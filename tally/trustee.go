package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"filippo.io/edwards25519"
)

// TrusteeKey represents a single trustee's public verification key as loaded
// from the DKG output. Index is the 1-based trustee index; Key is the
// Ristretto255 point H_i = g^{x_i}.
type TrusteeKey struct {
	Index int    `json:"index"`
	Key   string `json:"key"` // hex-encoded 32-byte compressed Ristretto255 point
}

// TrusteeKeySet holds the parsed trustee verification keys indexed by trustee
// number.
type TrusteeKeySet struct {
	Keys map[int]*edwards25519.Point
}

// LoadTrusteeKeys reads a JSON file containing trustee verification keys and
// returns a TrusteeKeySet. Each key must be a valid 32-byte compressed
// Ristretto255 point encoded as 64 hex characters. The function fails fast on
// any parse or validation error.
func LoadTrusteeKeys(path string) (*TrusteeKeySet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trustee keys: %w", err)
	}

	var entries []TrusteeKey
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse trustee keys JSON: %w", err)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("trustee key file is empty")
	}

	keys := make(map[int]*edwards25519.Point, len(entries))
	for _, entry := range entries {
		if entry.Index < 1 {
			return nil, fmt.Errorf("trustee index must be >= 1, got %d", entry.Index)
		}
		if _, dup := keys[entry.Index]; dup {
			return nil, fmt.Errorf("duplicate trustee index %d", entry.Index)
		}

		pointBytes, err := hex.DecodeString(entry.Key)
		if err != nil {
			return nil, fmt.Errorf("trustee %d: invalid hex: %w", entry.Index, err)
		}
		if len(pointBytes) != 32 {
			return nil, fmt.Errorf("trustee %d: expected 32 bytes, got %d", entry.Index, len(pointBytes))
		}

		point, err := new(edwards25519.Point).SetBytes(pointBytes)
		if err != nil {
			return nil, fmt.Errorf("trustee %d: invalid ristretto255 point: %w", entry.Index, err)
		}

		keys[entry.Index] = point
	}

	return &TrusteeKeySet{Keys: keys}, nil
}
