package threshold

import (
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
)

// mustDKG runs a (threshold, numParties) DKG.
func mustDKG(t *testing.T, threshold, numParties int) *DKGResult {
	t.Helper()
	result, err := RunDKG(threshold, numParties)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	return result
}

// dkgKeys maps each participant's Shamir index to its verification key.
func dkgKeys(result *DKGResult) map[int]*ristretto255.Element {
	keys := make(map[int]*ristretto255.Element, len(result.Participants))
	for _, p := range result.Participants {
		keys[p.ID] = p.VerificationKey
	}
	return keys
}

// dkgPartials has each participant at indices partially decrypt ct.
func dkgPartials(t *testing.T, result *DKGResult, sc SlotContext, ct *elgamal.Ciphertext, indices []int) []*Partial {
	t.Helper()
	partials := make([]*Partial, len(indices))
	for i, idx := range indices {
		p := result.Participants[idx-1]
		pd, err := PartialDecrypt(sc, p.ID, p.CombinedShare, ct)
		if err != nil {
			t.Fatalf("participant %d: PartialDecrypt: %v", idx, err)
		}
		partials[i] = pd
	}
	return partials
}

func TestDKGFullProtocol(t *testing.T) {
	result := mustDKG(t, 5, 9)
	if result.ElectionPublicKey == nil {
		t.Fatal("election public key should not be nil")
	}
	if len(result.Participants) != 9 {
		t.Fatalf("expected 9 participants, got %d", len(result.Participants))
	}

	// Encrypt and threshold-decrypt
	ct := mustEncrypt(t, result.ElectionPublicKey, 7)
	sc := testSlotContext(ct)

	partials := dkgPartials(t, result, sc, ct, []int{1, 2, 3, 4, 5})

	m, err := Combine(sc, ct, partials, dkgKeys(result), 5, 100)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if m != 7 {
		t.Fatalf("expected 7, got %d", m)
	}
}

func TestDKGDifferentSubset(t *testing.T) {
	result := mustDKG(t, 5, 9)

	ct := mustEncrypt(t, result.ElectionPublicKey, 99)
	sc := testSlotContext(ct)

	// Use a different subset
	partials := dkgPartials(t, result, sc, ct, []int{2, 4, 6, 8, 9})

	m, err := Combine(sc, ct, partials, dkgKeys(result), 5, 200)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if m != 99 {
		t.Fatalf("expected 99, got %d", m)
	}
}

func TestDKGWithProofs(t *testing.T) {
	result := mustDKG(t, 5, 9)

	ct := mustEncrypt(t, result.ElectionPublicKey, 3)
	sc := testSlotContext(ct)

	indices := []int{1, 3, 5, 7, 9}
	partials := dkgPartials(t, result, sc, ct, indices)
	for i, idx := range indices {
		p := result.Participants[idx-1]
		if err := VerifyPartial(sc, ct, partials[i], p.VerificationKey); err != nil {
			t.Fatalf("participant %d: proof should verify: %v", idx, err)
		}
	}

	m, err := Combine(sc, ct, partials, dkgKeys(result), 5, 100)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if m != 3 {
		t.Fatalf("expected 3, got %d", m)
	}
}

func TestDKGInvalidThreshold(t *testing.T) {
	for _, tc := range []struct{ threshold, numParties int }{
		{10, 5}, {0, 5}, {-1, 5}, {1, -1},
	} {
		if _, err := RunDKG(tc.threshold, tc.numParties); err == nil {
			t.Fatalf("RunDKG(%d, %d) should fail", tc.threshold, tc.numParties)
		}
	}
}

func TestFiveOfNineSubsetsAgree(t *testing.T) {
	result := mustDKG(t, 5, 9)
	keys := dkgKeys(result)

	const want = 1234
	ct := mustEncrypt(t, result.ElectionPublicKey, want)
	sc := testSlotContext(ct)

	for _, indices := range [][]int{
		{1, 2, 3, 4, 5},
		{5, 6, 7, 8, 9},
		{1, 3, 5, 7, 9},
	} {
		partials := dkgPartials(t, result, sc, ct, indices)
		m, err := Combine(sc, ct, partials, keys, 5, 2000)
		if err != nil {
			t.Fatalf("subset %v: Combine: %v", indices, err)
		}
		if m != want {
			t.Fatalf("subset %v: got %d, want %d", indices, m, want)
		}
	}
}
