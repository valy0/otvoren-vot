package internal

import (
	"testing"

	"filippo.io/edwards25519"
)

func TestBSGS(t *testing.T) {
	// g^42 should solve to 42
	target := new(edwards25519.Point).ScalarBaseMult(ScalarFromInt(42))
	m := BabyStepGiantStep(target, 1000)
	if m != 42 {
		t.Fatalf("expected 42, got %d", m)
	}
}

func TestBSGSZero(t *testing.T) {
	target := edwards25519.NewIdentityPoint() // g^0
	m := BabyStepGiantStep(target, 1000)
	if m != 0 {
		t.Fatalf("expected 0, got %d", m)
	}
}

func TestBSGSNotFound(t *testing.T) {
	// Value outside range
	target := new(edwards25519.Point).ScalarBaseMult(ScalarFromInt(5000))
	m := BabyStepGiantStep(target, 100)
	if m != -1 {
		t.Fatalf("expected -1 for out-of-range, got %d", m)
	}
}

func TestScalarFromInt(t *testing.T) {
	s := ScalarFromInt(0)
	zero := edwards25519.NewScalar()
	if s.Equal(zero) != 1 {
		t.Fatal("ScalarFromInt(0) should be zero scalar")
	}
}
