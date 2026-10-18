package internal

import (
	"testing"

	"github.com/gtank/ristretto255"
)

func mustBaseMult(t *testing.T, n int) *ristretto255.Element {
	t.Helper()
	e, err := ScalarBaseMultInt(n)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestBSGS(t *testing.T) {
	// g^42 should solve to 42
	target := mustBaseMult(t, 42)
	m := BabyStepGiantStep(target, 1000)
	if m != 42 {
		t.Fatalf("expected 42, got %d", m)
	}
}

func TestBSGSZero(t *testing.T) {
	target := ristretto255.NewIdentityElement() // g^0
	m := BabyStepGiantStep(target, 1000)
	if m != 0 {
		t.Fatalf("expected 0, got %d", m)
	}
}

func TestBSGSNotFound(t *testing.T) {
	// Value outside range
	target := mustBaseMult(t, 5000)
	m := BabyStepGiantStep(target, 100)
	if m != -1 {
		t.Fatalf("expected -1 for out-of-range, got %d", m)
	}
}

func TestScalarFromInt(t *testing.T) {
	s, err := ScalarFromInt(0)
	if err != nil {
		t.Fatal(err)
	}
	zero := ristretto255.NewScalar()
	if s.Equal(zero) != 1 {
		t.Fatal("ScalarFromInt(0) should be zero scalar")
	}
}
