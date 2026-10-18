package threshold

import (
	"errors"
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

// mustDealer returns a dealer for a (threshold, numParties) sharing.
func mustDealer(t *testing.T, threshold, numParties int) *Dealer {
	t.Helper()
	d, err := NewDealer(threshold, numParties)
	if err != nil {
		t.Fatalf("NewDealer(%d, %d): %v", threshold, numParties, err)
	}
	return d
}

// sharesAt returns the dealer's shares for the given 1-based indices.
func sharesAt(d *Dealer, indices []int) []*ristretto255.Scalar {
	shares := make([]*ristretto255.Scalar, len(indices))
	for i, idx := range indices {
		shares[i] = d.Shares[idx-1]
	}
	return shares
}

// mustInterpolate reconstructs f(0) from the shares at indices.
func mustInterpolate(t *testing.T, d *Dealer, indices []int) *ristretto255.Scalar {
	t.Helper()
	secret, err := LagrangeInterpolate(sharesAt(d, indices), indices)
	if err != nil {
		t.Fatalf("LagrangeInterpolate(%v): %v", indices, err)
	}
	return secret
}

func TestFeldmanShareGeneration(t *testing.T) {
	dealer := mustDealer(t, 5, 9)
	if len(dealer.Commitments) != 5 {
		t.Fatalf("expected 5 commitments, got %d", len(dealer.Commitments))
	}
	if len(dealer.Shares) != 9 {
		t.Fatalf("expected 9 shares, got %d", len(dealer.Shares))
	}
}

func TestNewDealerBounds(t *testing.T) {
	for _, tc := range []struct{ threshold, numParties int }{
		{0, 5}, {-1, 5}, {6, 5}, {1, 0}, {1, -1},
	} {
		if d, err := NewDealer(tc.threshold, tc.numParties); err == nil {
			t.Fatalf("NewDealer(%d, %d) = %v, want an error", tc.threshold, tc.numParties, d)
		}
	}
	for _, tc := range []struct{ threshold, numParties int }{
		{1, 1}, {5, 5}, {5, 9},
	} {
		if _, err := NewDealer(tc.threshold, tc.numParties); err != nil {
			t.Fatalf("NewDealer(%d, %d): %v", tc.threshold, tc.numParties, err)
		}
	}
}

func TestFeldmanShareVerification(t *testing.T) {
	dealer := mustDealer(t, 5, 9)
	for i := 0; i < 9; i++ {
		if !VerifyShare(dealer.Shares[i], i+1, 5, dealer.Commitments) {
			t.Fatalf("share %d should verify", i+1)
		}
	}
}

func TestFeldmanShareVerificationTampered(t *testing.T) {
	dealer := mustDealer(t, 5, 9)
	tampered := ristretto255.NewScalar().Add(dealer.Shares[0], dealer.Shares[1])
	if VerifyShare(tampered, 1, 5, dealer.Commitments) {
		t.Fatal("tampered share should NOT verify")
	}
}

// TestVerifyShareRejectsExtraCommitments is L5: the commitment count must equal
// the threshold, so a dealer cannot raise the degree of its polynomial.
func TestVerifyShareRejectsExtraCommitments(t *testing.T) {
	dealer := mustDealer(t, 5, 9)

	// An identity 6th commitment leaves the Feldman equation true, so only
	// the count check rejects it.
	extra := append(append([]*ristretto255.Element{}, dealer.Commitments...), ristretto255.NewIdentityElement())
	for i := 0; i < 9; i++ {
		if VerifyShare(dealer.Shares[i], i+1, 5, extra) {
			t.Fatalf("share %d verified against 6 commitments with threshold 5", i+1)
		}
	}

	// A t=6 polynomial: its shares satisfy its own 6 commitments, but 5 of
	// them cannot reconstruct the secret, so threshold 5 must refuse them.
	high := mustDealer(t, 6, 9)
	for i := 0; i < 9; i++ {
		if !VerifyShare(high.Shares[i], i+1, 6, high.Commitments) {
			t.Fatalf("share %d of the t=6 dealer should verify with threshold 6", i+1)
		}
		if VerifyShare(high.Shares[i], i+1, 5, high.Commitments) {
			t.Fatalf("share %d of a t=6 polynomial verified with threshold 5", i+1)
		}
	}

	// Too few commitments.
	if VerifyShare(dealer.Shares[0], 1, 5, dealer.Commitments[:4]) {
		t.Fatal("share verified against 4 commitments with threshold 5")
	}
}

func TestVerifyShareRejectsMalformed(t *testing.T) {
	dealer := mustDealer(t, 5, 9)

	// Index 0 is the secret itself: s = f(0) satisfies the equation at x = 0.
	if VerifyShare(dealer.Secret(), 0, 5, dealer.Commitments) {
		t.Fatal("index 0 should NOT verify")
	}
	if VerifyShare(dealer.Shares[0], -1, 5, dealer.Commitments) {
		t.Fatal("negative index should NOT verify")
	}
	if VerifyShare(nil, 1, 5, dealer.Commitments) {
		t.Fatal("nil share should NOT verify")
	}
	withNil := append([]*ristretto255.Element{}, dealer.Commitments...)
	withNil[2] = nil
	if VerifyShare(dealer.Shares[0], 1, 5, withNil) {
		t.Fatal("nil commitment should NOT verify")
	}
	if VerifyShare(ristretto255.NewScalar(), 1, 0, nil) {
		t.Fatal("threshold 0 with no commitments should NOT verify")
	}
}

func TestFeldmanReconstruction(t *testing.T) {
	dealer := mustDealer(t, 5, 9)
	secret := mustInterpolate(t, dealer, []int{1, 2, 3, 4, 5})
	if secret.Equal(dealer.Secret()) != 1 {
		t.Fatal("reconstructed secret should match")
	}
}

func TestFeldmanReconstructionDifferentSubset(t *testing.T) {
	dealer := mustDealer(t, 5, 9)
	secret := mustInterpolate(t, dealer, []int{3, 5, 7, 8, 9})
	if secret.Equal(dealer.Secret()) != 1 {
		t.Fatal("any 5-of-9 should reconstruct the same secret")
	}
}

func TestLagrangeInterpolateRoundTrip(t *testing.T) {
	dealer := mustDealer(t, 3, 5)

	subsets := [][]int{
		{1, 2, 3},
		{1, 3, 5},
		{2, 4, 5},
		{3, 4, 5},
	}

	for _, indices := range subsets {
		secret := mustInterpolate(t, dealer, indices)
		if secret.Equal(dealer.Secret()) != 1 {
			t.Fatalf("subset %v should reconstruct the original secret", indices)
		}
	}
}

func TestLagrangeInterpolateBelowThreshold(t *testing.T) {
	dealer := mustDealer(t, 3, 5)

	// Only 2 shares — below threshold of 3
	secret := mustInterpolate(t, dealer, []int{1, 4})
	if secret.Equal(dealer.Secret()) == 1 {
		t.Fatal("2-of-5 should NOT reconstruct correctly (with overwhelming probability)")
	}
}

func TestFeldmanInsufficientShares(t *testing.T) {
	dealer := mustDealer(t, 5, 9)
	// Only 4 shares — should NOT reconstruct correctly
	secret := mustInterpolate(t, dealer, []int{1, 2, 3, 4})
	if secret.Equal(dealer.Secret()) == 1 {
		t.Fatal("4-of-9 should NOT reconstruct correctly (with overwhelming probability)")
	}
}

// TestLagrangeCoefficientSpecExample checks the worked example of
// docs/protocol/threshold.md section 5.2: for T = {1, 3, 5, 7, 9},
// λ₁ = 945 / 384, i.e. λ₁ · 384 = 945 (mod q).
func TestLagrangeCoefficientSpecExample(t *testing.T) {
	lambda, err := LagrangeCoefficient([]int{1, 3, 5, 7, 9}, 0)
	if err != nil {
		t.Fatalf("LagrangeCoefficient: %v", err)
	}
	s384, _ := internal.ScalarFromInt(384)
	s945, _ := internal.ScalarFromInt(945)
	if ristretto255.NewScalar().Multiply(lambda, s384).Equal(s945) != 1 {
		t.Fatal("λ₁ · 384 should equal 945")
	}
}

func TestLagrangeRejectsBadIndices(t *testing.T) {
	for _, tc := range []struct {
		name    string
		indices []int
		pos     int
		want    error
	}{
		{"duplicate", []int{1, 2, 2}, 0, ErrDuplicateIndex},
		{"duplicate at pos", []int{1, 2, 2}, 1, ErrDuplicateIndex},
		{"index 0", []int{0, 1, 2}, 1, ErrBadIndex},
		{"negative index", []int{1, -2, 3}, 0, ErrBadIndex},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LagrangeCoefficient(tc.indices, tc.pos); !errors.Is(err, tc.want) {
				t.Fatalf("LagrangeCoefficient(%v, %d): got %v, want %v", tc.indices, tc.pos, err, tc.want)
			}
			shares := make([]*ristretto255.Scalar, len(tc.indices))
			for i := range shares {
				shares[i] = internal.RandomScalar()
			}
			if _, err := LagrangeInterpolate(shares, tc.indices); !errors.Is(err, tc.want) {
				t.Fatalf("LagrangeInterpolate(%v): got %v, want %v", tc.indices, err, tc.want)
			}
		})
	}

	for _, pos := range []int{-1, 3} {
		if _, err := LagrangeCoefficient([]int{1, 2, 3}, pos); err == nil {
			t.Fatalf("LagrangeCoefficient pos %d: want an error", pos)
		}
	}
	if _, err := LagrangeCoefficient(nil, 0); err == nil {
		t.Fatal("LagrangeCoefficient with no indices: want an error")
	}

	s := internal.RandomScalar()
	if _, err := LagrangeInterpolate([]*ristretto255.Scalar{s}, []int{1, 2}); err == nil {
		t.Fatal("LagrangeInterpolate with mismatched lengths: want an error")
	}
	if _, err := LagrangeInterpolate(nil, nil); err == nil {
		t.Fatal("LagrangeInterpolate with no shares: want an error")
	}
	if _, err := LagrangeInterpolate([]*ristretto255.Scalar{s, nil}, []int{1, 2}); err == nil {
		t.Fatal("LagrangeInterpolate with a nil share: want an error")
	}
}
