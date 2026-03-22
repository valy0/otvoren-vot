package proof

import (
	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

const cpDomain = "otvoren-vot.chaum-pedersen"

// ChaumPedersenProof proves that two group elements share the same discrete log.
// Given g, h, A=g^x, B=h^x, proves knowledge of x.
type ChaumPedersenProof struct {
	U *edwards25519.Point  // g^k
	V *edwards25519.Point  // h^k
	Z *edwards25519.Scalar // k + e*x
}

// ProveChaumPedersen creates a proof that A=g^x and B=h^x.
func ProveChaumPedersen(g, h, A, B *edwards25519.Point, x *edwards25519.Scalar) *ChaumPedersenProof {
	k := internal.RandomScalar()
	u := new(edwards25519.Point).ScalarMult(k, g)
	v := new(edwards25519.Point).ScalarMult(k, h)

	e := internal.FiatShamir(cpDomain,
		g.Bytes(), h.Bytes(),
		A.Bytes(), B.Bytes(),
		u.Bytes(), v.Bytes())

	z := new(edwards25519.Scalar).MultiplyAdd(e, x, k) // z = k + e*x

	return &ChaumPedersenProof{U: u, V: v, Z: z}
}

// VerifyChaumPedersen verifies the proof.
func VerifyChaumPedersen(g, h, A, B *edwards25519.Point, p *ChaumPedersenProof) bool {
	e := internal.FiatShamir(cpDomain,
		g.Bytes(), h.Bytes(),
		A.Bytes(), B.Bytes(),
		p.U.Bytes(), p.V.Bytes())

	// Check g^z == u + A*e
	gz := new(edwards25519.Point).ScalarMult(p.Z, g)
	ae := new(edwards25519.Point).ScalarMult(e, A)
	rhs1 := new(edwards25519.Point).Add(p.U, ae)
	if gz.Equal(rhs1) != 1 {
		return false
	}

	// Check h^z == v + B*e
	hz := new(edwards25519.Point).ScalarMult(p.Z, h)
	be := new(edwards25519.Point).ScalarMult(e, B)
	rhs2 := new(edwards25519.Point).Add(p.V, be)
	if hz.Equal(rhs2) != 1 {
		return false
	}

	return true
}
