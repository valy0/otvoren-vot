package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/group"
)

func TestLoadTrusteeKeys(t *testing.T) {
	// Generate test points: H_i = g * x_i for random scalars x_i
	type testTrustee struct {
		index int
		point *ristretto255.Element
	}

	trustees := make([]testTrustee, 3)
	for i := range trustees {
		scalar, err := randomScalar()
		if err != nil {
			t.Fatalf("generate scalar %d: %v", i, err)
		}
		point := ristretto255.NewIdentityElement().ScalarBaseMult(scalar)
		trustees[i] = testTrustee{index: i + 1, point: point}
	}

	// Write JSON file
	entries := make([]TrusteeKey, len(trustees))
	for i, tr := range trustees {
		entries[i] = TrusteeKey{
			Index: tr.index,
			Key:   hex.EncodeToString(tr.point.Bytes()),
		}
	}
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	path := filepath.Join(t.TempDir(), "trustees.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Load and verify
	ks, err := LoadTrusteeKeys(path)
	if err != nil {
		t.Fatalf("LoadTrusteeKeys: %v", err)
	}

	if len(ks.Keys) != len(trustees) {
		t.Fatalf("expected %d keys, got %d", len(trustees), len(ks.Keys))
	}

	for _, tr := range trustees {
		got, ok := ks.Keys[tr.index]
		if !ok {
			t.Fatalf("missing key for index %d", tr.index)
		}
		if got.Equal(tr.point) != 1 {
			t.Fatalf("key mismatch at index %d", tr.index)
		}
	}
}

func TestLoadTrusteeKeysErrors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		_, err := LoadTrusteeKeys("/nonexistent/path.json")
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("empty array", func(t *testing.T) {
		path := writeTempJSON(t, []TrusteeKey{})
		_, err := LoadTrusteeKeys(path)
		if err == nil {
			t.Fatal("expected error for empty array")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.json")
		os.WriteFile(path, []byte("not json"), 0o644)
		_, err := LoadTrusteeKeys(path)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("bad hex", func(t *testing.T) {
		path := writeTempJSON(t, []TrusteeKey{{Index: 1, Key: "zzzz"}})
		_, err := LoadTrusteeKeys(path)
		if err == nil {
			t.Fatal("expected error for bad hex")
		}
	})

	t.Run("wrong length", func(t *testing.T) {
		path := writeTempJSON(t, []TrusteeKey{{Index: 1, Key: "abcd"}})
		_, err := LoadTrusteeKeys(path)
		if err == nil {
			t.Fatal("expected error for wrong length")
		}
	})

	t.Run("invalid point", func(t *testing.T) {
		// 0x02 followed by 31 zero bytes is not a valid ristretto255 encoding.
		badBytes := make([]byte, 32)
		badBytes[0] = 0x02
		badHex := hex.EncodeToString(badBytes)
		path := writeTempJSON(t, []TrusteeKey{{Index: 1, Key: badHex}})
		_, err := LoadTrusteeKeys(path)
		if err == nil {
			t.Fatal("expected error for invalid point")
		}
	})

	t.Run("duplicate index", func(t *testing.T) {
		scalar, _ := randomScalar()
		pt := ristretto255.NewIdentityElement().ScalarBaseMult(scalar)
		keyHex := hex.EncodeToString(pt.Bytes())
		path := writeTempJSON(t, []TrusteeKey{
			{Index: 1, Key: keyHex},
			{Index: 1, Key: keyHex},
		})
		_, err := LoadTrusteeKeys(path)
		if err == nil {
			t.Fatal("expected error for duplicate index")
		}
	})

	t.Run("zero index", func(t *testing.T) {
		scalar, _ := randomScalar()
		pt := ristretto255.NewIdentityElement().ScalarBaseMult(scalar)
		keyHex := hex.EncodeToString(pt.Bytes())
		path := writeTempJSON(t, []TrusteeKey{{Index: 0, Key: keyHex}})
		_, err := LoadTrusteeKeys(path)
		if err == nil {
			t.Fatal("expected error for zero index")
		}
	})
}

// TestLoadTrusteeKeysRejectsEdwardsAndIdentity: a key must decode as a
// canonical, non-identity ristretto255 element. The Edwards basepoint's
// encoding is not a canonical ristretto255 encoding, and the all-zero
// encoding is the identity.
func TestLoadTrusteeKeysRejectsEdwardsAndIdentity(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want error
	}{
		{"edwards basepoint", "5866666666666666666666666666666666666666666666666666666666666666", group.ErrNonCanonical},
		{"identity", strings.Repeat("0", 64), group.ErrIdentity},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := writeTempJSON(t, []TrusteeKey{{Index: 1, Key: c.key}})
			ks, err := LoadTrusteeKeys(path)
			if !errors.Is(err, c.want) {
				t.Fatalf("LoadTrusteeKeys = (%v, %v), want an error wrapping %v", ks, err, c.want)
			}
		})
	}
}

// randomScalar generates a cryptographically random ristretto255 scalar.
func randomScalar() (*ristretto255.Scalar, error) {
	var buf [64]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return nil, err
	}
	s, err := ristretto255.NewScalar().SetUniformBytes(buf[:])
	if err != nil {
		return nil, err
	}
	return s, nil
}

// writeTempJSON marshals v to a temporary JSON file and returns its path.
func writeTempJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "trustees.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}
