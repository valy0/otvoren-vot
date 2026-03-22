package threshold

import (
	"testing"

	"github.com/valy0/otvoren-vot/crypto/elgamal"
)

func TestDKGFullProtocol(t *testing.T) {
	result, err := RunDKG(5, 9)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	if result.ElectionPublicKey == nil {
		t.Fatal("election public key should not be nil")
	}
	if len(result.Participants) != 9 {
		t.Fatalf("expected 9 participants, got %d", len(result.Participants))
	}

	// Encrypt and threshold-decrypt
	ct, _ := elgamal.Encrypt(result.ElectionPublicKey, 7)

	indices := []int{1, 2, 3, 4, 5}
	partials := make([]*PartialDecryption, 5)
	for i, idx := range indices {
		p := result.Participants[idx-1]
		partials[i] = PartialDecrypt(p.CombinedShare, ct)
	}

	m := CombinePartials(ct, partials, indices, 100)
	if m != 7 {
		t.Fatalf("expected 7, got %d", m)
	}
}

func TestDKGDifferentSubset(t *testing.T) {
	result, err := RunDKG(5, 9)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}

	ct, _ := elgamal.Encrypt(result.ElectionPublicKey, 99)

	// Use a different subset
	indices := []int{2, 4, 6, 8, 9}
	partials := make([]*PartialDecryption, 5)
	for i, idx := range indices {
		p := result.Participants[idx-1]
		partials[i] = PartialDecrypt(p.CombinedShare, ct)
	}

	m := CombinePartials(ct, partials, indices, 200)
	if m != 99 {
		t.Fatalf("expected 99, got %d", m)
	}
}

func TestDKGWithProofs(t *testing.T) {
	result, err := RunDKG(5, 9)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}

	ct, _ := elgamal.Encrypt(result.ElectionPublicKey, 3)

	indices := []int{1, 3, 5, 7, 9}
	partials := make([]*PartialDecryption, 5)
	for i, idx := range indices {
		p := result.Participants[idx-1]
		partials[i] = PartialDecryptWithProof(p.CombinedShare, ct, p.VerificationKey)
		if !VerifyPartialDecryption(ct, partials[i], p.VerificationKey) {
			t.Fatalf("participant %d: proof should verify", idx)
		}
	}

	m := CombinePartials(ct, partials, indices, 100)
	if m != 3 {
		t.Fatalf("expected 3, got %d", m)
	}
}

func TestDKGInvalidThreshold(t *testing.T) {
	_, err := RunDKG(10, 5)
	if err == nil {
		t.Fatal("threshold > numParties should fail")
	}
}
