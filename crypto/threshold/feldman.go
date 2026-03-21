package threshold

import (
	"math/big"

	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

// Dealer holds the state for Feldman's Verifiable Secret Sharing.
type Dealer struct {
	coefficients []*edwards25519.Scalar
	Commitments  []*edwards25519.Point  // g^{a_k} for each coefficient
	Shares       []*edwards25519.Scalar // f(i) for i = 1..n
}

// NewDealer generates a random polynomial of degree t-1 and computes shares for n parties.
func NewDealer(threshold, numParties int) *Dealer {
	coeffs := make([]*edwards25519.Scalar, threshold)
	commitments := make([]*edwards25519.Point, threshold)

	for k := 0; k < threshold; k++ {
		coeffs[k] = internal.RandomScalar()
		commitments[k] = new(edwards25519.Point).ScalarBaseMult(coeffs[k])
	}

	shares := make([]*edwards25519.Scalar, numParties)
	for i := 1; i <= numParties; i++ {
		shares[i-1] = evaluatePolynomial(coeffs, i)
	}

	return &Dealer{
		coefficients: coeffs,
		Commitments:  commitments,
		Shares:       shares,
	}
}

// Secret returns the secret value a_0.
func (d *Dealer) Secret() *edwards25519.Scalar {
	return d.coefficients[0]
}

// PublicKey returns g^{a_0}.
func (d *Dealer) PublicKey() *edwards25519.Point {
	return d.Commitments[0]
}

// VerifyShare checks that share s_i is consistent with published commitments.
// index is 1-based.
func VerifyShare(share *edwards25519.Scalar, index int, commitments []*edwards25519.Point) bool {
	lhs := new(edwards25519.Point).ScalarBaseMult(share)

	rhs := edwards25519.NewIdentityPoint()
	iPow := big.NewInt(1)
	iBig := big.NewInt(int64(index))

	for k, ck := range commitments {
		if k > 0 {
			iPow.Mul(iPow, iBig)
		}
		exp := scalarFromBigInt(iPow)
		term := new(edwards25519.Point).ScalarMult(exp, ck)
		rhs.Add(rhs, term)
	}

	return lhs.Equal(rhs) == 1
}

// LagrangeInterpolate reconstructs the secret from t shares.
// indices are 1-based.
func LagrangeInterpolate(shares []*edwards25519.Scalar, indices []int) *edwards25519.Scalar {
	secret := edwards25519.NewScalar()
	for i, si := range shares {
		lambda := LagrangeCoefficient(indices, i)
		term := new(edwards25519.Scalar).Multiply(lambda, si)
		secret.Add(secret, term)
	}
	return secret
}

// LagrangeCoefficient computes the Lagrange basis coefficient for index myIdx
// in the set of indices.
func LagrangeCoefficient(indices []int, myIdx int) *edwards25519.Scalar {
	q := edwards25519Order()
	num := big.NewInt(1)
	den := big.NewInt(1)
	xi := big.NewInt(int64(indices[myIdx]))

	for j, xj := range indices {
		if j == myIdx {
			continue
		}
		xjBig := big.NewInt(int64(xj))
		num.Mul(num, xjBig)
		num.Mod(num, q)
		diff := new(big.Int).Sub(xjBig, xi)
		diff.Mod(diff, q)
		den.Mul(den, diff)
		den.Mod(den, q)
	}

	denInv := new(big.Int).ModInverse(den, q)
	result := new(big.Int).Mul(num, denInv)
	result.Mod(result, q)

	return scalarFromBigInt(result)
}

func evaluatePolynomial(coeffs []*edwards25519.Scalar, x int) *edwards25519.Scalar {
	xScalar := internal.ScalarFromInt(x)
	result := edwards25519.NewScalar()
	for k := len(coeffs) - 1; k >= 0; k-- {
		result.Multiply(result, xScalar)
		result.Add(result, coeffs[k])
	}
	return result
}

func edwards25519Order() *big.Int {
	q, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	return q
}

func scalarFromBigInt(n *big.Int) *edwards25519.Scalar {
	q := edwards25519Order()
	n = new(big.Int).Mod(n, q)
	var buf [32]byte
	b := n.Bytes()
	for i, v := range b {
		buf[len(b)-1-i] = v
	}
	s, err := edwards25519.NewScalar().SetCanonicalBytes(buf[:])
	if err != nil {
		panic("scalarFromBigInt: " + err.Error())
	}
	return s
}
