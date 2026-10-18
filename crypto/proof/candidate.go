package proof

import (
	"fmt"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
)

const (
	candidateSumDomain = "otvoren-vot.candidate-sum-01-proof"
	consistencyDomain  = "otvoren-vot.candidate-consistency-proof"
)

// ProveCandidateSum proves, bound to ctx, that a party's candidate vector sums
// to 0 or 1. aggCt is HomomorphicAdd(candidateVector...), rSum is the sum of
// encryption randomness for the candidate vector, and sum is the actual
// plaintext sum (0 = no preference, 1 = one candidate selected). ctx.Index is
// the party index p (docs/protocol/ballot-proofs.md section 8.4).
func ProveCandidateSum(ctx Context, publicKey *ristretto255.Element, aggCt *elgamal.Ciphertext, sum int, rSum *ristretto255.Scalar) (*BinaryProof, error) {
	return proveBinaryWithDomain(candidateSumDomain, ctx, publicKey, aggCt, sum, rSum)
}

// VerifyCandidateSum verifies under ctx that a party's candidate vector sums
// to 0 or 1. Errors are as for VerifyBinary.
func VerifyCandidateSum(ctx Context, publicKey *ristretto255.Element, aggCt *elgamal.Ciphertext, p *BinaryProof) error {
	return verifyBinaryWithDomain(candidateSumDomain, ctx, publicKey, aggCt, p)
}

// ProveConsistency proves, bound to ctx, that party_bit - candidate_sum ∈ {0, 1}.
//
// This enforces the conditional constraint: if a party is not selected (m_p = 0),
// then the candidate sum for that party must also be 0. The valid combinations are:
//
//	m_p=0, S_p=0  =>  diff=0  (party not selected, no candidate)
//	m_p=1, S_p=0  =>  diff=1  (party selected, no candidate preference)
//	m_p=1, S_p=1  =>  diff=0  (party selected, one candidate preferred)
//
// The proof is applied uniformly to ALL parties (not just non-selected ones)
// to avoid leaking which party was selected via proof structure.
//
// partyCt encrypts m_p with randomness r_p.
// candSumCt encrypts S_p with randomness R_p (sum of candidate randomness).
// diff = m_p - S_p, rDiff = r_p - R_p. ctx.Index is the party index p
// (docs/protocol/ballot-proofs.md section 8.4).
func ProveConsistency(ctx Context, publicKey *ristretto255.Element, partyCt, candSumCt *elgamal.Ciphertext, diff int, rDiff *ristretto255.Scalar) (*BinaryProof, error) {
	if err := checkConsistencyStatement(ctx, publicKey, partyCt, candSumCt); err != nil {
		return nil, err
	}
	if err := checkBitWitness(diff, rDiff); err != nil {
		return nil, fmt.Errorf("%s: %w", consistencyDomain, err)
	}
	diffCt := homomorphicSubtract(partyCt, candSumCt)
	return proveBinaryWithDomain(consistencyDomain, ctx, publicKey, diffCt, diff, rDiff)
}

// VerifyConsistency verifies the conditional consistency proof under ctx.
// The verifier recomputes the difference ciphertext from the party and candidate
// sum ciphertexts, then verifies the binary proof on the difference. Errors
// are as for VerifyBinary.
func VerifyConsistency(ctx Context, publicKey *ristretto255.Element, partyCt, candSumCt *elgamal.Ciphertext, p *BinaryProof) error {
	if err := checkConsistencyStatement(ctx, publicKey, partyCt, candSumCt); err != nil {
		return err
	}
	if err := p.check(); err != nil {
		return fmt.Errorf("%s: %w", consistencyDomain, err)
	}
	diffCt := homomorphicSubtract(partyCt, candSumCt)
	return verifyBinaryWithDomain(consistencyDomain, ctx, publicKey, diffCt, p)
}

func checkConsistencyStatement(ctx Context, publicKey *ristretto255.Element, partyCt, candSumCt *elgamal.Ciphertext) error {
	if err := ctx.validate(); err != nil {
		return fmt.Errorf("%s: %w", consistencyDomain, err)
	}
	if err := checkPublicKey(publicKey); err != nil {
		return fmt.Errorf("%s: %w", consistencyDomain, err)
	}
	if err := checkCiphertext("party ciphertext", partyCt); err != nil {
		return fmt.Errorf("%s: %w", consistencyDomain, err)
	}
	if err := checkCiphertext("candidate-sum ciphertext", candSumCt); err != nil {
		return fmt.Errorf("%s: %w", consistencyDomain, err)
	}
	return nil
}

// homomorphicSubtract computes a - b component-wise on ciphertexts.
// Result encrypts (m_a - m_b) with randomness (r_a - r_b).
func homomorphicSubtract(a, b *elgamal.Ciphertext) *elgamal.Ciphertext {
	return &elgamal.Ciphertext{
		C1: ristretto255.NewIdentityElement().Subtract(a.C1, b.C1),
		C2: ristretto255.NewIdentityElement().Subtract(a.C2, b.C2),
	}
}
