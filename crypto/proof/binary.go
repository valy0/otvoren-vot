package proof

import (
	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

const binaryDomain = "otvoren-vot.ballot-binary-proof"

// BinaryProof proves an ElGamal ciphertext encrypts 0 or 1.
type BinaryProof struct {
	A0, A1 *edwards25519.Point  // commitments for branches
	B0, B1 *edwards25519.Point
	E0, E1 *edwards25519.Scalar // challenges
	Z0, Z1 *edwards25519.Scalar // responses
}

// ProveBinary creates a ZK proof that ct encrypts m ∈ {0, 1}.
func ProveBinary(publicKey *edwards25519.Point, ct *elgamal.Ciphertext, m int, r *edwards25519.Scalar) *BinaryProof {
	g := edwards25519.NewGeneratorPoint()
	if m == 0 {
		return proveBinaryReal0(g, publicKey, ct, r)
	}
	return proveBinaryReal1(g, publicKey, ct, r)
}

func fiatShamirBinary(publicKey *edwards25519.Point, ct *elgamal.Ciphertext, a0, b0, a1, b1 *edwards25519.Point) *edwards25519.Scalar {
	return internal.FiatShamir(binaryDomain,
		publicKey.Bytes(), // CRITICAL: include public key
		ct.C1.Bytes(), ct.C2.Bytes(),
		a0.Bytes(), b0.Bytes(),
		a1.Bytes(), b1.Bytes())
}

// m=0 is real, m=1 is simulated
func proveBinaryReal0(g, h *edwards25519.Point, ct *elgamal.Ciphertext, r *edwards25519.Scalar) *BinaryProof {
	k := internal.RandomScalar()
	a0 := new(edwards25519.Point).ScalarBaseMult(k)        // g^k
	b0 := new(edwards25519.Point).ScalarMult(k, h)         // h^k

	// Simulate branch 1
	e1 := internal.RandomScalar()
	z1 := internal.RandomScalar()

	// a1 = g^z1 * c1^{-e1}
	gz1 := new(edwards25519.Point).ScalarBaseMult(z1)
	c1e1 := new(edwards25519.Point).ScalarMult(e1, ct.C1)
	a1 := new(edwards25519.Point).Add(gz1, new(edwards25519.Point).Negate(c1e1))

	// b1 = h^z1 * (c2 - g)^{-e1}
	hz1 := new(edwards25519.Point).ScalarMult(z1, h)
	c2MinusG := new(edwards25519.Point).Add(ct.C2, new(edwards25519.Point).Negate(g))
	c2ge1 := new(edwards25519.Point).ScalarMult(e1, c2MinusG)
	b1 := new(edwards25519.Point).Add(hz1, new(edwards25519.Point).Negate(c2ge1))

	e := fiatShamirBinary(h, ct, a0, b0, a1, b1)
	e0 := new(edwards25519.Scalar).Subtract(e, e1)
	z0 := new(edwards25519.Scalar).MultiplyAdd(e0, r, k) // z0 = k + e0*r

	return &BinaryProof{A0: a0, A1: a1, B0: b0, B1: b1, E0: e0, E1: e1, Z0: z0, Z1: z1}
}

// m=1 is real, m=0 is simulated
func proveBinaryReal1(g, h *edwards25519.Point, ct *elgamal.Ciphertext, r *edwards25519.Scalar) *BinaryProof {
	// Simulate branch 0
	e0 := internal.RandomScalar()
	z0 := internal.RandomScalar()

	gz0 := new(edwards25519.Point).ScalarBaseMult(z0)
	c1e0 := new(edwards25519.Point).ScalarMult(e0, ct.C1)
	a0 := new(edwards25519.Point).Add(gz0, new(edwards25519.Point).Negate(c1e0))

	hz0 := new(edwards25519.Point).ScalarMult(z0, h)
	c2e0 := new(edwards25519.Point).ScalarMult(e0, ct.C2)
	b0 := new(edwards25519.Point).Add(hz0, new(edwards25519.Point).Negate(c2e0))

	// Real branch 1
	k := internal.RandomScalar()
	a1 := new(edwards25519.Point).ScalarBaseMult(k)
	b1 := new(edwards25519.Point).ScalarMult(k, h)

	e := fiatShamirBinary(h, ct, a0, b0, a1, b1)
	e1 := new(edwards25519.Scalar).Subtract(e, e0)
	z1 := new(edwards25519.Scalar).MultiplyAdd(e1, r, k)

	return &BinaryProof{A0: a0, A1: a1, B0: b0, B1: b1, E0: e0, E1: e1, Z0: z0, Z1: z1}
}

// VerifyBinary verifies a binary proof.
func VerifyBinary(publicKey *edwards25519.Point, ct *elgamal.Ciphertext, p *BinaryProof) bool {
	g := edwards25519.NewGeneratorPoint()

	e := fiatShamirBinary(publicKey, ct, p.A0, p.B0, p.A1, p.B1)

	// Check e0 + e1 = e
	eSum := new(edwards25519.Scalar).Add(p.E0, p.E1)
	if eSum.Equal(e) != 1 {
		return false
	}

	// Branch 0: g^z0 == a0 + c1*e0
	lhs := new(edwards25519.Point).ScalarBaseMult(p.Z0)
	rhs := new(edwards25519.Point).Add(p.A0, new(edwards25519.Point).ScalarMult(p.E0, ct.C1))
	if lhs.Equal(rhs) != 1 {
		return false
	}

	// Branch 0: h^z0 == b0 + c2*e0
	lhs = new(edwards25519.Point).ScalarMult(p.Z0, publicKey)
	rhs = new(edwards25519.Point).Add(p.B0, new(edwards25519.Point).ScalarMult(p.E0, ct.C2))
	if lhs.Equal(rhs) != 1 {
		return false
	}

	// Branch 1: g^z1 == a1 + c1*e1
	lhs = new(edwards25519.Point).ScalarBaseMult(p.Z1)
	rhs = new(edwards25519.Point).Add(p.A1, new(edwards25519.Point).ScalarMult(p.E1, ct.C1))
	if lhs.Equal(rhs) != 1 {
		return false
	}

	// Branch 1: h^z1 == b1 + (c2-g)*e1
	c2MinusG := new(edwards25519.Point).Add(ct.C2, new(edwards25519.Point).Negate(g))
	lhs = new(edwards25519.Point).ScalarMult(p.Z1, publicKey)
	rhs = new(edwards25519.Point).Add(p.B1, new(edwards25519.Point).ScalarMult(p.E1, c2MinusG))
	if lhs.Equal(rhs) != 1 {
		return false
	}

	return true
}
