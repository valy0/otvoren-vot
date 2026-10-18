package proof

import (
	"fmt"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

const binaryDomain = "otvoren-vot.ballot-binary-proof"

// BinaryProof proves an ElGamal ciphertext encrypts 0 or 1.
type BinaryProof struct {
	A0, A1 *ristretto255.Element // commitments for branches
	B0, B1 *ristretto255.Element
	E0, E1 *ristretto255.Scalar // challenges
	Z0, Z1 *ristretto255.Scalar // responses
}

// ProveBinary creates a ZK proof, bound to ctx, that ct encrypts m ∈ {0, 1}.
func ProveBinary(ctx Context, publicKey *ristretto255.Element, ct *elgamal.Ciphertext, m int, r *ristretto255.Scalar) (*BinaryProof, error) {
	return proveBinaryWithDomain(binaryDomain, ctx, publicKey, ct, m, r)
}

// VerifyBinary verifies a binary proof under ctx. It returns nil for a valid
// proof, an error wrapping ErrInvalidProof when the equations do not hold, and
// an error wrapping ErrMalformed for unusable input.
//
// Inputs that come from the wire must be decoded with crypto/group (or
// elgamal.CiphertextFromBytes) first. VerifyBinary refuses an identity public
// key (ErrMalformed), but it does not reject an identity ciphertext component
// or proof element: it shares its input checks with VerifyCandidateSum and
// VerifyConsistency, whose statements are derived aggregates that may
// legitimately be the identity.
func VerifyBinary(ctx Context, publicKey *ristretto255.Element, ct *elgamal.Ciphertext, p *BinaryProof) error {
	return verifyBinaryWithDomain(binaryDomain, ctx, publicKey, ct, p)
}

func checkBinaryStatement(ctx Context, publicKey *ristretto255.Element, ct *elgamal.Ciphertext) error {
	if err := ctx.validate(); err != nil {
		return err
	}
	if err := checkPublicKey(publicKey); err != nil {
		return err
	}
	return checkCiphertext("ciphertext", ct)
}

func (p *BinaryProof) check() error {
	if p == nil {
		return fmt.Errorf("nil binary proof: %w", ErrMalformed)
	}
	if p.A0 == nil || p.A1 == nil || p.B0 == nil || p.B1 == nil ||
		p.E0 == nil || p.E1 == nil || p.Z0 == nil || p.Z1 == nil {
		return fmt.Errorf("binary proof has a nil field: %w", ErrMalformed)
	}
	return nil
}

// proveBinaryWithDomain creates a ZK proof that ct encrypts m ∈ {0, 1}
// using the given domain separator for Fiat-Shamir. This allows reusing
// the disjunctive Chaum-Pedersen structure for different proof contexts
// (e.g., candidate sum proofs, consistency proofs) without cross-protocol
// challenge collisions.
func proveBinaryWithDomain(domain string, ctx Context, publicKey *ristretto255.Element, ct *elgamal.Ciphertext, m int, r *ristretto255.Scalar) (*BinaryProof, error) {
	if err := checkBinaryStatement(ctx, publicKey, ct); err != nil {
		return nil, fmt.Errorf("%s: %w", domain, err)
	}
	if err := checkBitWitness(m, r); err != nil {
		return nil, fmt.Errorf("%s: %w", domain, err)
	}
	if m == 0 {
		return proveBinaryReal0(domain, ctx, publicKey, ct, r), nil
	}
	return proveBinaryReal1(domain, ctx, publicKey, ct, r), nil
}

// verifyBinaryWithDomain verifies a binary proof using the given domain separator.
func verifyBinaryWithDomain(domain string, ctx Context, publicKey *ristretto255.Element, ct *elgamal.Ciphertext, p *BinaryProof) error {
	if err := checkBinaryStatement(ctx, publicKey, ct); err != nil {
		return fmt.Errorf("%s: %w", domain, err)
	}
	if err := p.check(); err != nil {
		return fmt.Errorf("%s: %w", domain, err)
	}

	g := ristretto255.NewGeneratorElement()

	e := binaryChallenge(domain, ctx, publicKey, ct, p.A0, p.B0, p.A1, p.B1)

	// Check e0 + e1 = e
	eSum := ristretto255.NewScalar().Add(p.E0, p.E1)
	if eSum.Equal(e) != 1 {
		return fmt.Errorf("%s: challenges do not sum to the transcript challenge: %w", domain, ErrInvalidProof)
	}

	// Branch 0: g^z0 == a0 + c1*e0
	lhs := ristretto255.NewIdentityElement().ScalarBaseMult(p.Z0)
	rhs := ristretto255.NewIdentityElement().Add(p.A0, ristretto255.NewIdentityElement().ScalarMult(p.E0, ct.C1))
	if lhs.Equal(rhs) != 1 {
		return fmt.Errorf("%s: branch 0 g-equation fails: %w", domain, ErrInvalidProof)
	}

	// Branch 0: h^z0 == b0 + c2*e0
	lhs = ristretto255.NewIdentityElement().ScalarMult(p.Z0, publicKey)
	rhs = ristretto255.NewIdentityElement().Add(p.B0, ristretto255.NewIdentityElement().ScalarMult(p.E0, ct.C2))
	if lhs.Equal(rhs) != 1 {
		return fmt.Errorf("%s: branch 0 h-equation fails: %w", domain, ErrInvalidProof)
	}

	// Branch 1: g^z1 == a1 + c1*e1
	lhs = ristretto255.NewIdentityElement().ScalarBaseMult(p.Z1)
	rhs = ristretto255.NewIdentityElement().Add(p.A1, ristretto255.NewIdentityElement().ScalarMult(p.E1, ct.C1))
	if lhs.Equal(rhs) != 1 {
		return fmt.Errorf("%s: branch 1 g-equation fails: %w", domain, ErrInvalidProof)
	}

	// Branch 1: h^z1 == b1 + (c2-g)*e1
	c2MinusG := ristretto255.NewIdentityElement().Subtract(ct.C2, g)
	lhs = ristretto255.NewIdentityElement().ScalarMult(p.Z1, publicKey)
	rhs = ristretto255.NewIdentityElement().Add(p.B1, ristretto255.NewIdentityElement().ScalarMult(p.E1, c2MinusG))
	if lhs.Equal(rhs) != 1 {
		return fmt.Errorf("%s: branch 1 h-equation fails: %w", domain, ErrInvalidProof)
	}

	return nil
}

// binaryChallenge is the transcript of docs/protocol/fiat-shamir.md, "Binary
// Proof": FiatShamir(domain, election_id, ballot_id, index, pk, C1, C2, A0, B0, A1, B1).
func binaryChallenge(domain string, ctx Context, publicKey *ristretto255.Element, ct *elgamal.Ciphertext, a0, b0, a1, b1 *ristretto255.Element) *ristretto255.Scalar {
	return ballotChallenge(domain, ctx,
		publicKey.Bytes(), // CRITICAL: include public key
		ct.C1.Bytes(), ct.C2.Bytes(),
		a0.Bytes(), b0.Bytes(),
		a1.Bytes(), b1.Bytes())
}

// m=0 is real, m=1 is simulated
func proveBinaryReal0(domain string, ctx Context, h *ristretto255.Element, ct *elgamal.Ciphertext, r *ristretto255.Scalar) *BinaryProof {
	g := ristretto255.NewGeneratorElement()

	k := internal.RandomScalar()
	a0 := ristretto255.NewIdentityElement().ScalarBaseMult(k) // g^k
	b0 := ristretto255.NewIdentityElement().ScalarMult(k, h)  // h^k

	// Simulate branch 1
	e1 := internal.RandomScalar()
	z1 := internal.RandomScalar()

	// a1 = g^z1 * c1^{-e1}
	gz1 := ristretto255.NewIdentityElement().ScalarBaseMult(z1)
	c1e1 := ristretto255.NewIdentityElement().ScalarMult(e1, ct.C1)
	a1 := ristretto255.NewIdentityElement().Subtract(gz1, c1e1)

	// b1 = h^z1 * (c2 - g)^{-e1}
	hz1 := ristretto255.NewIdentityElement().ScalarMult(z1, h)
	c2MinusG := ristretto255.NewIdentityElement().Subtract(ct.C2, g)
	c2ge1 := ristretto255.NewIdentityElement().ScalarMult(e1, c2MinusG)
	b1 := ristretto255.NewIdentityElement().Subtract(hz1, c2ge1)

	e := binaryChallenge(domain, ctx, h, ct, a0, b0, a1, b1)
	e0 := ristretto255.NewScalar().Subtract(e, e1)
	z0 := ristretto255.NewScalar().Multiply(e0, r) // z0 = k + e0*r
	z0.Add(z0, k)

	return &BinaryProof{A0: a0, A1: a1, B0: b0, B1: b1, E0: e0, E1: e1, Z0: z0, Z1: z1}
}

// m=1 is real, m=0 is simulated
func proveBinaryReal1(domain string, ctx Context, h *ristretto255.Element, ct *elgamal.Ciphertext, r *ristretto255.Scalar) *BinaryProof {
	// Simulate branch 0
	e0 := internal.RandomScalar()
	z0 := internal.RandomScalar()

	gz0 := ristretto255.NewIdentityElement().ScalarBaseMult(z0)
	c1e0 := ristretto255.NewIdentityElement().ScalarMult(e0, ct.C1)
	a0 := ristretto255.NewIdentityElement().Subtract(gz0, c1e0)

	hz0 := ristretto255.NewIdentityElement().ScalarMult(z0, h)
	c2e0 := ristretto255.NewIdentityElement().ScalarMult(e0, ct.C2)
	b0 := ristretto255.NewIdentityElement().Subtract(hz0, c2e0)

	// Real branch 1
	k := internal.RandomScalar()
	a1 := ristretto255.NewIdentityElement().ScalarBaseMult(k)
	b1 := ristretto255.NewIdentityElement().ScalarMult(k, h)

	e := binaryChallenge(domain, ctx, h, ct, a0, b0, a1, b1)
	e1 := ristretto255.NewScalar().Subtract(e, e0)
	z1 := ristretto255.NewScalar().Multiply(e1, r) // z1 = k + e1*r
	z1.Add(z1, k)

	return &BinaryProof{A0: a0, A1: a1, B0: b0, B1: b1, E0: e0, E1: e1, Z0: z0, Z1: z1}
}
