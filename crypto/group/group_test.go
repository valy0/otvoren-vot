package group

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/gtank/ristretto255"
)

type rfcVectors struct {
	Multiples    []string `json:"multiples"`
	BadEncodings []string `json:"bad_encodings"`
}

func loadVectors(t *testing.T) rfcVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/rfc9496.json")
	if err != nil {
		t.Fatal(err)
	}
	var v rfcVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func smallScalar(t *testing.T, k byte) *ristretto255.Scalar {
	t.Helper()
	b := make([]byte, ScalarSize)
	b[0] = k
	s, err := ristretto255.NewScalar().SetCanonicalBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMultiplesOfGeneratorMatchRFC9496(t *testing.T) {
	v := loadVectors(t)
	if len(v.Multiples) != 16 {
		t.Fatalf("want 16 multiples, got %d", len(v.Multiples))
	}
	const generator = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
	if v.Multiples[1] != generator {
		t.Fatalf("multiples[1] = %s, want %s", v.Multiples[1], generator)
	}
	for k := 1; k <= 15; k++ {
		want := mustHex(t, v.Multiples[k])
		got := ristretto255.NewIdentityElement().ScalarBaseMult(smallScalar(t, byte(k))).Bytes()
		if !bytes.Equal(got, want) {
			t.Errorf("k=%d: ScalarBaseMult = %x, want %x", k, got, want)
		}
		e, err := DecodeElement(want)
		if err != nil {
			t.Errorf("k=%d: DecodeElement: %v", k, err)
			continue
		}
		if !bytes.Equal(e.Bytes(), want) {
			t.Errorf("k=%d: round trip = %x, want %x", k, e.Bytes(), want)
		}
	}
}

func TestDecodeRejectsRFC9496BadEncodings(t *testing.T) {
	v := loadVectors(t)
	if len(v.BadEncodings) == 0 {
		t.Fatal("no bad encodings loaded")
	}
	for _, h := range v.BadEncodings {
		_, err := DecodeElement(mustHex(t, h))
		if !errors.Is(err, ErrNonCanonical) {
			t.Errorf("%s: err = %v, want ErrNonCanonical", h, err)
		}
	}
}

func TestDecodeRejectsEdwardsTorsionPoint(t *testing.T) {
	// Edwards (0, -1) in compressed form: the C2 finding vector.
	b := mustHex(t, "ec"+strings.Repeat("ff", 30)+"7f")
	if _, err := DecodeElement(b); err == nil {
		t.Fatal("Edwards torsion point decoded without error")
	}
}

func TestDecodeRejectsIdentity(t *testing.T) {
	_, err := DecodeElement(make([]byte, ElementSize))
	if !errors.Is(err, ErrIdentity) {
		t.Fatalf("err = %v, want ErrIdentity", err)
	}
}

func TestDecodeRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 31, 33} {
		if _, err := DecodeElement(make([]byte, n)); !errors.Is(err, ErrLength) {
			t.Errorf("DecodeElement len %d: err = %v, want ErrLength", n, err)
		}
		if _, err := DecodeScalar(make([]byte, n)); !errors.Is(err, ErrLength) {
			t.Errorf("DecodeScalar len %d: err = %v, want ErrLength", n, err)
		}
	}
}

func TestDecodeScalarCanonical(t *testing.T) {
	l := mustHex(t, "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
	if _, err := DecodeScalar(l); !errors.Is(err, ErrNonCanonical) {
		t.Errorf("l: err = %v, want ErrNonCanonical", err)
	}
	lm1 := append([]byte(nil), l...)
	lm1[0]-- // l is odd-ending 0xed, so l-1 only changes byte 0
	s, err := DecodeScalar(lm1)
	if err != nil {
		t.Fatalf("l-1 rejected: %v", err)
	}
	if !bytes.Equal(s.Bytes(), lm1) {
		t.Errorf("l-1 round trip = %x, want %x", s.Bytes(), lm1)
	}
}
