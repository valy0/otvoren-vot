package threshold

import (
	"errors"
	"fmt"
	"math"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

var (
	// ErrDuplicateIndex is returned when a trustee index appears twice in a
	// set of shares or partial decryptions.
	ErrDuplicateIndex = errors.New("threshold: duplicate trustee index")
	// ErrBadIndex is returned for a trustee index outside 1..2^32-1. Index 0
	// would evaluate the polynomial at the secret, and the transcript carries
	// the index as a u32.
	ErrBadIndex = errors.New("threshold: trustee index out of range")
)

// Dealer holds the state for Feldman's Verifiable Secret Sharing.
type Dealer struct {
	coefficients []*ristretto255.Scalar
	Commitments  []*ristretto255.Element // a_k * G for each coefficient
	Shares       []*ristretto255.Scalar  // f(i) for i = 1..n
}

// NewDealer generates a random polynomial of degree threshold-1 and computes
// shares for numParties parties. It requires 1 <= threshold <= numParties.
func NewDealer(threshold, numParties int) (*Dealer, error) {
	if err := checkThreshold(threshold, numParties); err != nil {
		return nil, err
	}

	coeffs := make([]*ristretto255.Scalar, threshold)
	commitments := make([]*ristretto255.Element, threshold)
	for k := range threshold {
		coeffs[k] = internal.RandomScalar()
		commitments[k] = ristretto255.NewIdentityElement().ScalarBaseMult(coeffs[k])
	}

	shares := make([]*ristretto255.Scalar, numParties)
	for i := 1; i <= numParties; i++ {
		s, err := evaluatePolynomial(coeffs, i)
		if err != nil {
			return nil, err
		}
		shares[i-1] = s
	}

	return &Dealer{
		coefficients: coeffs,
		Commitments:  commitments,
		Shares:       shares,
	}, nil
}

// Secret returns the secret value a_0.
func (d *Dealer) Secret() *ristretto255.Scalar {
	return d.coefficients[0]
}

// PublicKey returns a_0 * G.
func (d *Dealer) PublicKey() *ristretto255.Element {
	return d.Commitments[0]
}

// VerifyShare checks that share s_i is consistent with the published
// commitments: s_i * G = Σ_k i^k * C_k (docs/protocol/threshold.md section
// 1.4). index is the 1-based Shamir index.
//
// It returns false unless there are exactly threshold commitments, so a
// dealer cannot publish a polynomial of higher degree than the threshold, and
// unless index >= 1 and the share and every commitment are non-nil.
func VerifyShare(share *ristretto255.Scalar, index, threshold int, commitments []*ristretto255.Element) bool {
	if threshold < 1 || len(commitments) != threshold {
		return false
	}
	if share == nil || checkIndex(index) != nil {
		return false
	}
	for _, c := range commitments {
		if c == nil {
			return false
		}
	}

	x, err := internal.ScalarFromInt(index)
	if err != nil {
		return false
	}
	pow, err := internal.ScalarFromInt(1)
	if err != nil {
		return false
	}
	powers := make([]*ristretto255.Scalar, len(commitments))
	for k := range commitments {
		powers[k] = ristretto255.NewScalar().Set(pow)
		pow.Multiply(pow, x)
	}

	lhs := ristretto255.NewIdentityElement().ScalarBaseMult(share)
	rhs := ristretto255.NewIdentityElement().MultiScalarMult(powers, commitments)
	return lhs.Equal(rhs) == 1
}

// LagrangeInterpolate reconstructs f(0) from shares at the 1-based indices.
func LagrangeInterpolate(shares []*ristretto255.Scalar, indices []int) (*ristretto255.Scalar, error) {
	if len(shares) == 0 {
		return nil, errors.New("threshold: no shares to interpolate")
	}
	if len(shares) != len(indices) {
		return nil, fmt.Errorf("threshold: %d shares but %d indices", len(shares), len(indices))
	}
	if err := checkIndices(indices); err != nil {
		return nil, err
	}

	secret := ristretto255.NewScalar()
	for i, si := range shares {
		if si == nil {
			return nil, fmt.Errorf("threshold: share at position %d is nil", i)
		}
		lambda, err := lagrangeAt(indices, i)
		if err != nil {
			return nil, err
		}
		secret.Add(secret, ristretto255.NewScalar().Multiply(lambda, si))
	}
	return secret, nil
}

// LagrangeCoefficient computes the Lagrange basis coefficient at x = 0 for
// indices[pos] within indices (docs/protocol/threshold.md section 5.1):
//
//	λ = Π_{j ≠ pos} x_j / (x_j - x_pos)  (mod q)
//
// Every index must be in 1..2^32-1 (else ErrBadIndex) and distinct (else
// ErrDuplicateIndex), so no denominator is zero.
func LagrangeCoefficient(indices []int, pos int) (*ristretto255.Scalar, error) {
	if err := checkIndices(indices); err != nil {
		return nil, err
	}
	if pos < 0 || pos >= len(indices) {
		return nil, fmt.Errorf("threshold: position %d outside %d indices", pos, len(indices))
	}
	return lagrangeAt(indices, pos)
}

// lagrangeAt computes the coefficient for indices[pos]. The caller has
// checked indices with checkIndices and pos against len(indices): distinct
// indices of at most 2^32-1 are distinct mod q, so every x_j - x_pos is
// non-zero and invertible.
func lagrangeAt(indices []int, pos int) (*ristretto255.Scalar, error) {
	xi, err := internal.ScalarFromInt(indices[pos])
	if err != nil {
		return nil, fmt.Errorf("threshold: index %d: %w", indices[pos], err)
	}
	num, err := internal.ScalarFromInt(1)
	if err != nil {
		return nil, err
	}
	den, err := internal.ScalarFromInt(1)
	if err != nil {
		return nil, err
	}
	for j, idx := range indices {
		if j == pos {
			continue
		}
		xj, err := internal.ScalarFromInt(idx)
		if err != nil {
			return nil, fmt.Errorf("threshold: index %d: %w", idx, err)
		}
		num.Multiply(num, xj)
		den.Multiply(den, ristretto255.NewScalar().Subtract(xj, xi))
	}
	return num.Multiply(num, ristretto255.NewScalar().Invert(den)), nil
}

// checkThreshold requires 1 <= threshold <= numParties, with every party
// index 1..numParties a valid trustee index.
func checkThreshold(threshold, numParties int) error {
	if threshold < 1 || threshold > numParties {
		return fmt.Errorf("threshold: need 1 <= threshold (%d) <= numParties (%d)", threshold, numParties)
	}
	return checkIndex(numParties)
}

// checkIndex rejects a trustee index outside 1..2^32-1.
func checkIndex(i int) error {
	if i < 1 || uint64(i) > math.MaxUint32 {
		return fmt.Errorf("index %d: %w", i, ErrBadIndex)
	}
	return nil
}

// checkIndices checks every index with checkIndex, then rejects duplicates.
func checkIndices(indices []int) error {
	for _, idx := range indices {
		if err := checkIndex(idx); err != nil {
			return err
		}
	}
	seen := make(map[int]bool, len(indices))
	for _, idx := range indices {
		if seen[idx] {
			return fmt.Errorf("index %d: %w", idx, ErrDuplicateIndex)
		}
		seen[idx] = true
	}
	return nil
}

func evaluatePolynomial(coeffs []*ristretto255.Scalar, x int) (*ristretto255.Scalar, error) {
	xScalar, err := internal.ScalarFromInt(x)
	if err != nil {
		return nil, fmt.Errorf("threshold: evaluating at %d: %w", x, err)
	}
	result := ristretto255.NewScalar()
	for k := len(coeffs) - 1; k >= 0; k-- {
		result.Multiply(result, xScalar)
		result.Add(result, coeffs[k])
	}
	return result, nil
}
