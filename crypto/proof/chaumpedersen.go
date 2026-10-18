package proof

import (
	"fmt"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

const cpDomain = "otvoren-vot.chaum-pedersen"

// ChaumPedersenProof proves that two group elements share the same discrete log.
// Given g, h, A=g^x, B=h^x, proves knowledge of x.
type ChaumPedersenProof struct {
	U *ristretto255.Element // g^k
	V *ristretto255.Element // h^k
	Z *ristretto255.Scalar  // k + e*x
}

// ProveChaumPedersen creates a proof that A=g^x and B=h^x, bound to context.
//
// The transcript is FiatShamir(domain, context[0], ..., context[n-1], g, h, A,
// B, u, v): each context slice is its own length-prefixed field, in the order
// given, before the statement. The caller decides what the context means; for
// a partial decryption it is the seven context fields of
// docs/protocol/fiat-shamir.md, "Partial-Decryption Proof". A nil or empty
// context is allowed.
func ProveChaumPedersen(context [][]byte, g, h, A, B *ristretto255.Element, x *ristretto255.Scalar) (*ChaumPedersenProof, error) {
	if err := checkCPStatement(g, h, A, B); err != nil {
		return nil, err
	}
	if x == nil {
		return nil, fmt.Errorf("%s: nil witness: %w", cpDomain, ErrMalformed)
	}

	k := internal.RandomScalar()
	u := ristretto255.NewIdentityElement().ScalarMult(k, g)
	v := ristretto255.NewIdentityElement().ScalarMult(k, h)

	e := cpChallenge(context, g, h, A, B, u, v)

	z := ristretto255.NewScalar().Multiply(e, x) // z = k + e*x
	z.Add(z, k)

	return &ChaumPedersenProof{U: u, V: v, Z: z}, nil
}

// VerifyChaumPedersen verifies the proof under context. It returns nil for a
// valid proof, an error wrapping ErrInvalidProof when the equations do not
// hold, and an error wrapping ErrMalformed for a nil statement element or
// proof field.
//
// VerifyChaumPedersen rejects only nil elements, never the identity. In a
// partial decryption, h is the tally's c1 and B = share·c1, both of which are
// the identity when the tally's randomness sums to 0. Elements that come from
// the wire must be decoded with crypto/group first wherever the identity is
// not a legitimate value.
func VerifyChaumPedersen(context [][]byte, g, h, A, B *ristretto255.Element, p *ChaumPedersenProof) error {
	if err := checkCPStatement(g, h, A, B); err != nil {
		return err
	}
	if p == nil {
		return fmt.Errorf("%s: nil proof: %w", cpDomain, ErrMalformed)
	}
	if p.U == nil || p.V == nil || p.Z == nil {
		return fmt.Errorf("%s: proof has a nil field: %w", cpDomain, ErrMalformed)
	}

	e := cpChallenge(context, g, h, A, B, p.U, p.V)

	// Check g^z == u + A*e
	gz := ristretto255.NewIdentityElement().ScalarMult(p.Z, g)
	ae := ristretto255.NewIdentityElement().ScalarMult(e, A)
	rhs1 := ristretto255.NewIdentityElement().Add(p.U, ae)
	if gz.Equal(rhs1) != 1 {
		return fmt.Errorf("%s: g-equation fails: %w", cpDomain, ErrInvalidProof)
	}

	// Check h^z == v + B*e
	hz := ristretto255.NewIdentityElement().ScalarMult(p.Z, h)
	be := ristretto255.NewIdentityElement().ScalarMult(e, B)
	rhs2 := ristretto255.NewIdentityElement().Add(p.V, be)
	if hz.Equal(rhs2) != 1 {
		return fmt.Errorf("%s: h-equation fails: %w", cpDomain, ErrInvalidProof)
	}

	return nil
}

func checkCPStatement(g, h, A, B *ristretto255.Element) error {
	if g == nil || h == nil || A == nil || B == nil {
		return fmt.Errorf("%s: nil statement element: %w", cpDomain, ErrMalformed)
	}
	return nil
}

// cpChallenge computes FiatShamir(domain, context..., g, h, A, B, u, v).
func cpChallenge(context [][]byte, g, h, A, B, u, v *ristretto255.Element) *ristretto255.Scalar {
	fields := make([][]byte, 0, len(context)+6)
	fields = append(fields, context...)
	fields = append(fields,
		g.Bytes(), h.Bytes(),
		A.Bytes(), B.Bytes(),
		u.Bytes(), v.Bytes())
	return internal.FiatShamir(cpDomain, fields...)
}
