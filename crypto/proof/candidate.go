package proof

import (
	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
)

const (
	candidateSumDomain = "otvoren-vot.candidate-sum-01-proof"
	consistencyDomain  = "otvoren-vot.candidate-consistency-proof"
)

// ProveCandidateSum proves that a party's candidate vector sums to 0 or 1.
// aggCt is HomomorphicAdd(candidateVector...), rSum is the sum of encryption
// randomness for the candidate vector, and sum is the actual plaintext sum
// (0 = no preference, 1 = one candidate selected).
func ProveCandidateSum(publicKey *edwards25519.Point, aggCt *elgamal.Ciphertext, sum int, rSum *edwards25519.Scalar) *BinaryProof {
	return ProveBinaryWithDomain(candidateSumDomain, publicKey, aggCt, sum, rSum)
}

// VerifyCandidateSum verifies that a party's candidate vector sums to 0 or 1.
func VerifyCandidateSum(publicKey *edwards25519.Point, aggCt *elgamal.Ciphertext, p *BinaryProof) bool {
	return VerifyBinaryWithDomain(candidateSumDomain, publicKey, aggCt, p)
}

// ProveConsistency proves that party_bit - candidate_sum ∈ {0, 1}.
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
// diff = m_p - S_p, rDiff = r_p - R_p.
func ProveConsistency(publicKey *edwards25519.Point, partyCt, candSumCt *elgamal.Ciphertext, diff int, rDiff *edwards25519.Scalar) *BinaryProof {
	diffCt := homomorphicSubtract(partyCt, candSumCt)
	return ProveBinaryWithDomain(consistencyDomain, publicKey, diffCt, diff, rDiff)
}

// VerifyConsistency verifies the conditional consistency proof.
// The verifier recomputes the difference ciphertext from the party and candidate
// sum ciphertexts, then verifies the binary proof on the difference.
func VerifyConsistency(publicKey *edwards25519.Point, partyCt, candSumCt *elgamal.Ciphertext, p *BinaryProof) bool {
	diffCt := homomorphicSubtract(partyCt, candSumCt)
	return VerifyBinaryWithDomain(consistencyDomain, publicKey, diffCt, p)
}

// homomorphicSubtract computes a - b component-wise on ciphertexts.
// Result encrypts (m_a - m_b) with randomness (r_a - r_b).
func homomorphicSubtract(a, b *elgamal.Ciphertext) *elgamal.Ciphertext {
	return &elgamal.Ciphertext{
		C1: new(edwards25519.Point).Subtract(a.C1, b.C1),
		C2: new(edwards25519.Point).Subtract(a.C2, b.C2),
	}
}
