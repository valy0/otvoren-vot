package proof

import (
	"fmt"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

const sumDomain = "otvoren-vot.ballot-sum-proof"

// SumOneProof proves that ciphertexts encrypt values summing to 1.
type SumOneProof struct {
	A *ristretto255.Element
	B *ristretto255.Element
	Z *ristretto255.Scalar
}

// ProveSumOne creates a proof, bound to ctx, that the ciphertexts encrypt
// values summing to 1. rSum is the sum of all encryption randomness values.
func ProveSumOne(ctx Context, publicKey *ristretto255.Element, cts []*elgamal.Ciphertext, rSum *ristretto255.Scalar) (*SumOneProof, error) {
	if err := checkSumStatement(ctx, publicKey, cts); err != nil {
		return nil, err
	}
	if rSum == nil {
		return nil, fmt.Errorf("%s: nil randomness: %w", sumDomain, ErrMalformed)
	}
	aggCt := elgamal.HomomorphicAdd(cts...)

	k := internal.RandomScalar()
	a := ristretto255.NewIdentityElement().ScalarBaseMult(k)
	b := ristretto255.NewIdentityElement().ScalarMult(k, publicKey)

	e := sumChallenge(ctx, publicKey, aggCt, a, b)

	z := ristretto255.NewScalar().Multiply(e, rSum) // z = k + e*rSum
	z.Add(z, k)

	return &SumOneProof{A: a, B: b, Z: z}, nil
}

// VerifySumOne verifies under ctx that the ciphertexts encrypt values summing
// to 1. It returns nil for a valid proof, an error wrapping ErrInvalidProof
// when the equations do not hold, and an error wrapping ErrMalformed for
// unusable input.
//
// Inputs that come from the wire must be decoded with crypto/group (or
// elgamal.CiphertextFromBytes) first. VerifySumOne refuses an identity public
// key (ErrMalformed), but not an identity ciphertext component or proof
// element; the aggregate it derives from cts may legitimately be the identity.
func VerifySumOne(ctx Context, publicKey *ristretto255.Element, cts []*elgamal.Ciphertext, p *SumOneProof) error {
	if err := checkSumStatement(ctx, publicKey, cts); err != nil {
		return err
	}
	if p == nil {
		return fmt.Errorf("%s: nil proof: %w", sumDomain, ErrMalformed)
	}
	if p.A == nil || p.B == nil || p.Z == nil {
		return fmt.Errorf("%s: proof has a nil field: %w", sumDomain, ErrMalformed)
	}

	g := ristretto255.NewGeneratorElement()
	aggCt := elgamal.HomomorphicAdd(cts...)

	e := sumChallenge(ctx, publicKey, aggCt, p.A, p.B)

	// Check g^z == a + c1_agg * e
	lhs := ristretto255.NewIdentityElement().ScalarBaseMult(p.Z)
	rhs := ristretto255.NewIdentityElement().Add(p.A, ristretto255.NewIdentityElement().ScalarMult(e, aggCt.C1))
	if lhs.Equal(rhs) != 1 {
		return fmt.Errorf("%s: g-equation fails: %w", sumDomain, ErrInvalidProof)
	}

	// Check h^z == b + (c2_agg - g)^e
	// Because sum=1 means c2_agg = h^rSum * g^1, so c2_agg - g = h^rSum
	c2MinusG := ristretto255.NewIdentityElement().Subtract(aggCt.C2, g)
	lhs2 := ristretto255.NewIdentityElement().ScalarMult(p.Z, publicKey)
	rhs2 := ristretto255.NewIdentityElement().Add(p.B, ristretto255.NewIdentityElement().ScalarMult(e, c2MinusG))
	if lhs2.Equal(rhs2) != 1 {
		return fmt.Errorf("%s: h-equation fails: %w", sumDomain, ErrInvalidProof)
	}

	return nil
}

func checkSumStatement(ctx Context, publicKey *ristretto255.Element, cts []*elgamal.Ciphertext) error {
	if err := ctx.validate(); err != nil {
		return fmt.Errorf("%s: %w", sumDomain, err)
	}
	if err := checkPublicKey(publicKey); err != nil {
		return fmt.Errorf("%s: %w", sumDomain, err)
	}
	if len(cts) == 0 {
		return fmt.Errorf("%s: empty ciphertext vector: %w", sumDomain, ErrMalformed)
	}
	for i, ct := range cts {
		if err := checkCiphertext(fmt.Sprintf("ciphertext %d", i), ct); err != nil {
			return fmt.Errorf("%s: %w", sumDomain, err)
		}
	}
	return nil
}

// sumChallenge is the transcript of docs/protocol/fiat-shamir.md,
// "Sum-Equals-One Proof": FiatShamir(domain, election_id, ballot_id, index,
// pk, C1_agg, C2_agg, A, B).
func sumChallenge(ctx Context, publicKey *ristretto255.Element, aggCt *elgamal.Ciphertext, a, b *ristretto255.Element) *ristretto255.Scalar {
	return ballotChallenge(sumDomain, ctx,
		publicKey.Bytes(), // CRITICAL: include public key
		aggCt.C1.Bytes(), aggCt.C2.Bytes(),
		a.Bytes(), b.Bytes())
}
