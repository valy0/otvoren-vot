package internal

import (
	"math/big"

	"filippo.io/edwards25519"
)

// BabyStepGiantStep solves g^m = target for m in [0, max].
// Returns m, or -1 if not found.
func BabyStepGiantStep(target *edwards25519.Point, max int) int {
	step := 1
	for step*step < max {
		step++
	}

	g := edwards25519.NewGeneratorPoint()

	// Baby steps: build table of {g^j => j} for j = 0..step-1
	table := make(map[[32]byte]int, step)
	current := edwards25519.NewIdentityPoint()
	for j := 0; j < step; j++ {
		var key [32]byte
		copy(key[:], current.Bytes())
		table[key] = j
		current.Add(current, g)
	}

	// Giant step: g^{-step}
	stepScalar := ScalarFromInt(step)
	giantStep := new(edwards25519.Point).ScalarBaseMult(stepScalar)
	giantStep.Negate(giantStep)

	// Search
	gamma := new(edwards25519.Point).Set(target)
	for i := 0; i <= max/step+1; i++ {
		var key [32]byte
		copy(key[:], gamma.Bytes())
		if j, ok := table[key]; ok {
			return i*step + j
		}
		gamma.Add(gamma, giantStep)
	}
	return -1
}

// ScalarFromInt converts a non-negative integer to a Scalar.
func ScalarFromInt(n int) *edwards25519.Scalar {
	var buf [32]byte
	b := big.NewInt(int64(n)).Bytes()
	for i, v := range b {
		buf[len(b)-1-i] = v // little-endian
	}
	s, err := edwards25519.NewScalar().SetCanonicalBytes(buf[:])
	if err != nil {
		panic("ScalarFromInt: " + err.Error())
	}
	return s
}

// ScalarBaseMultInt computes g^m for small integer m.
func ScalarBaseMultInt(m int) *edwards25519.Point {
	if m == 0 {
		return edwards25519.NewIdentityPoint()
	}
	return new(edwards25519.Point).ScalarBaseMult(ScalarFromInt(m))
}
