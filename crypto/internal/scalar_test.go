package internal

import (
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

func TestHashToScalar(t *testing.T) {
	s1 := HashToScalar([]byte("otvoren-vot.test"), []byte("input1"))
	s2 := HashToScalar([]byte("otvoren-vot.test"), []byte("input2"))
	s3 := HashToScalar([]byte("otvoren-vot.test"), []byte("input1"))
	if s1.Equal(s2) == 1 {
		t.Fatal("different inputs should produce different scalars")
	}
	if s1.Equal(s3) != 1 {
		t.Fatal("same inputs should produce same scalar")
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
