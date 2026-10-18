package internal

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gtank/ristretto255"
)

// ErrNegative is returned when a negative integer is converted to a scalar.
var ErrNegative = errors.New("internal: negative integer")

// BabyStepGiantStep solves g^m = target for m in [0, max].
// Returns m, or -1 if there is no such m.
func BabyStepGiantStep(target *ristretto255.Element, max int) int {
	step := 1
	for step*step < max {
		step++
	}

	g := ristretto255.NewGeneratorElement()

	// Baby steps: build table of {g^j => j} for j = 0..step-1
	table := make(map[[32]byte]int, step)
	current := ristretto255.NewIdentityElement()
	for j := 0; j < step; j++ {
		var key [32]byte
		copy(key[:], current.Bytes())
		table[key] = j
		current.Add(current, g)
	}

	// Giant step: g^{-step}
	stepScalar, err := ScalarFromInt(step)
	if err != nil {
		panic("BabyStepGiantStep: " + err.Error()) // step is always positive
	}
	giantStep := ristretto255.NewIdentityElement().ScalarBaseMult(stepScalar)
	giantStep.Negate(giantStep)

	// Search. The last giant-step window can reach past max, so bound the result.
	gamma := ristretto255.NewIdentityElement().Set(target)
	for i := 0; i <= max/step+1; i++ {
		var key [32]byte
		copy(key[:], gamma.Bytes())
		if j, ok := table[key]; ok {
			if m := i*step + j; m <= max {
				return m
			}
			return -1
		}
		gamma.Add(gamma, giantStep)
	}
	return -1
}

// ScalarFromInt converts a non-negative integer to a Scalar.
// Negative input returns an error wrapping ErrNegative.
func ScalarFromInt(n int) (*ristretto255.Scalar, error) {
	if n < 0 {
		return nil, fmt.Errorf("scalar from %d: %w", n, ErrNegative)
	}
	var buf [32]byte
	binary.LittleEndian.PutUint64(buf[:8], uint64(n))
	s, err := ristretto255.NewScalar().SetCanonicalBytes(buf[:])
	if err != nil {
		return nil, fmt.Errorf("scalar from %d: %w", n, err)
	}
	return s, nil
}

// ScalarBaseMultInt computes g^m for a small non-negative integer m.
func ScalarBaseMultInt(m int) (*ristretto255.Element, error) {
	s, err := ScalarFromInt(m)
	if err != nil {
		return nil, err
	}
	return ristretto255.NewIdentityElement().ScalarBaseMult(s), nil
}
