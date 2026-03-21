package proof

import (
	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

const sumDomain = "otvoren-vot.ballot-sum-proof"

// SumOneProof proves that ciphertexts encrypt values summing to 1.
type SumOneProof struct {
	A *edwards25519.Point
	B *edwards25519.Point
	Z *edwards25519.Scalar
}

// ProveSumOne creates a proof that the ciphertexts encrypt values summing to 1.
// rSum is the sum of all encryption randomness values.
func ProveSumOne(publicKey *edwards25519.Point, cts []*elgamal.Ciphertext, rSum *edwards25519.Scalar) *SumOneProof {
	aggCt := elgamal.HomomorphicAdd(cts...)

	k := internal.RandomScalar()
	a := new(edwards25519.Point).ScalarBaseMult(k)
	b := new(edwards25519.Point).ScalarMult(k, publicKey)

	e := internal.FiatShamir(sumDomain,
		publicKey.Bytes(), // CRITICAL: include public key
		aggCt.C1.Bytes(), aggCt.C2.Bytes(),
		a.Bytes(), b.Bytes())

	z := new(edwards25519.Scalar).MultiplyAdd(e, rSum, k) // z = k + e*rSum

	return &SumOneProof{A: a, B: b, Z: z}
}

// VerifySumOne verifies that the ciphertexts encrypt values summing to 1.
func VerifySumOne(publicKey *edwards25519.Point, cts []*elgamal.Ciphertext, p *SumOneProof) bool {
	g := edwards25519.NewGeneratorPoint()
	aggCt := elgamal.HomomorphicAdd(cts...)

	e := internal.FiatShamir(sumDomain,
		publicKey.Bytes(),
		aggCt.C1.Bytes(), aggCt.C2.Bytes(),
		p.A.Bytes(), p.B.Bytes())

	// Check g^z == a + c1_agg * e
	lhs := new(edwards25519.Point).ScalarBaseMult(p.Z)
	rhs := new(edwards25519.Point).Add(p.A, new(edwards25519.Point).ScalarMult(e, aggCt.C1))
	if lhs.Equal(rhs) != 1 {
		return false
	}

	// Check h^z == b + (c2_agg - g)^e
	// Because sum=1 means c2_agg = h^rSum * g^1, so c2_agg - g = h^rSum
	c2MinusG := new(edwards25519.Point).Add(aggCt.C2, new(edwards25519.Point).Negate(g))
	lhs2 := new(edwards25519.Point).ScalarMult(p.Z, publicKey)
	rhs2 := new(edwards25519.Point).Add(p.B, new(edwards25519.Point).ScalarMult(e, c2MinusG))
	if lhs2.Equal(rhs2) != 1 {
		return false
	}

	return true
}
