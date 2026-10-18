package internal

import (
	"crypto/sha512"
	"testing"

	"github.com/gtank/ristretto255"
)

func TestRandomScalar(t *testing.T) {
	s1 := RandomScalar()
	s2 := RandomScalar()
	if s1.Equal(s2) == 1 {
		t.Fatal("two random scalars should not be equal")
	}
}

func TestFiatShamir(t *testing.T) {
	e1 := FiatShamir("otvoren-vot.test-proof", []byte("data1"))
	e2 := FiatShamir("otvoren-vot.test-proof", []byte("data2"))
	e3 := FiatShamir("otvoren-vot.test-proof", []byte("data1"))
	if e1.Equal(e2) == 1 {
		t.Fatal("different data should produce different challenges")
	}
	if e1.Equal(e3) != 1 {
		t.Fatal("same data should produce same challenge")
	}
}

func TestSumScalars(t *testing.T) {
	s1 := RandomScalar()
	s2 := RandomScalar()
	sum := SumScalars([]*ristretto255.Scalar{s1, s2})
	expected := ristretto255.NewScalar().Add(s1, s2)
	if sum.Equal(expected) != 1 {
		t.Fatal("SumScalars should equal manual addition")
	}
}

// TestFiatShamirKnownAnswer pins the transcript framing independently of the
// implementation: the hash input is built by hand with literal u32be length
// prefixes.
func TestFiatShamirKnownAnswer(t *testing.T) {
	domain := "otvoren-vot.kat"
	d1 := []byte{0xaa, 0xbb, 0xcc}
	d2 := []byte{}
	d3 := []byte("слово") // 10 UTF-8 bytes

	var in []byte
	in = append(in, 0x00, 0x00, 0x00, 0x0f) // len(domain) = 15
	in = append(in, domain...)
	in = append(in, 0x00, 0x00, 0x00, 0x03) // len(d1) = 3
	in = append(in, d1...)
	in = append(in, 0x00, 0x00, 0x00, 0x00) // len(d2) = 0
	in = append(in, 0x00, 0x00, 0x00, 0x0a) // len(d3) = 10
	in = append(in, d3...)

	digest := sha512.Sum512(in)
	want, err := ristretto255.NewScalar().SetUniformBytes(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	got := FiatShamir(domain, d1, d2, d3)
	if got.Equal(want) != 1 {
		t.Fatal("FiatShamir does not match the hand-built transcript")
	}
}
