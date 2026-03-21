package threshold

import (
	"testing"

	"filippo.io/edwards25519"
)

func TestFeldmanShareGeneration(t *testing.T) {
	dealer := NewDealer(5, 9)
	if len(dealer.Commitments) != 5 {
		t.Fatalf("expected 5 commitments, got %d", len(dealer.Commitments))
	}
	if len(dealer.Shares) != 9 {
		t.Fatalf("expected 9 shares, got %d", len(dealer.Shares))
	}
}

func TestFeldmanShareVerification(t *testing.T) {
	dealer := NewDealer(5, 9)
	for i := 0; i < 9; i++ {
		if !VerifyShare(dealer.Shares[i], i+1, dealer.Commitments) {
			t.Fatalf("share %d should verify", i+1)
		}
	}
}

func TestFeldmanShareVerificationTampered(t *testing.T) {
	dealer := NewDealer(5, 9)
	tampered := new(edwards25519.Scalar).Add(dealer.Shares[0], dealer.Shares[1])
	if VerifyShare(tampered, 1, dealer.Commitments) {
		t.Fatal("tampered share should NOT verify")
	}
}

func TestFeldmanReconstruction(t *testing.T) {
	dealer := NewDealer(5, 9)
	indices := []int{1, 2, 3, 4, 5}
	shares := make([]*edwards25519.Scalar, 5)
	for i, idx := range indices {
		shares[i] = dealer.Shares[idx-1]
	}
	secret := LagrangeInterpolate(shares, indices)
	if secret.Equal(dealer.Secret()) != 1 {
		t.Fatal("reconstructed secret should match")
	}
}

func TestFeldmanReconstructionDifferentSubset(t *testing.T) {
	dealer := NewDealer(5, 9)
	indices := []int{3, 5, 7, 8, 9}
	shares := make([]*edwards25519.Scalar, 5)
	for i, idx := range indices {
		shares[i] = dealer.Shares[idx-1]
	}
	secret := LagrangeInterpolate(shares, indices)
	if secret.Equal(dealer.Secret()) != 1 {
		t.Fatal("any 5-of-9 should reconstruct the same secret")
	}
}

func TestFeldmanInsufficientShares(t *testing.T) {
	dealer := NewDealer(5, 9)
	// Only 4 shares — should NOT reconstruct correctly
	indices := []int{1, 2, 3, 4}
	shares := make([]*edwards25519.Scalar, 4)
	for i, idx := range indices {
		shares[i] = dealer.Shares[idx-1]
	}
	secret := LagrangeInterpolate(shares, indices)
	if secret.Equal(dealer.Secret()) == 1 {
		t.Fatal("4-of-9 should NOT reconstruct correctly (with overwhelming probability)")
	}
}
