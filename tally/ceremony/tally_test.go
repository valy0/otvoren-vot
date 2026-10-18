package ceremony

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/proof"
	"github.com/valy0/otvoren-vot/crypto/threshold"
)

// encodeBallots encrypts one party vote per entry of votes under pk and
// serializes each ballot as the bulletin board stores it.
func encodeBallots(t *testing.T, pk *ristretto255.Element, numParties int, votes []int) []SerializedBallot {
	t.Helper()
	ballots := make([]SerializedBallot, len(votes))
	for i, party := range votes {
		b, err := elgamal.EncodeBallot(pk, numParties, party)
		if err != nil {
			t.Fatalf("EncodeBallot: %v", err)
		}
		// Serialize party vector as hex ciphertexts
		pvHex := make([]string, numParties)
		for j, ct := range b.PartyVector {
			pvHex[j] = hex.EncodeToString(ct.Bytes())
		}
		encBallot, _ := json.Marshal(BallotData{PartyVector: pvHex})
		ballots[i] = SerializedBallot{
			BallotID:        "ballot-" + string(rune('0'+i)),
			EncryptedBallot: encBallot,
		}
	}
	return ballots
}

// tallyContexts builds one slot context per tally slot, bound to the digest
// of the tally's own encrypted sums.
func tallyContexts(tally *TallyResult) []threshold.SlotContext {
	digest := threshold.TallyDigest(tally.EncryptedSums)
	out := make([]threshold.SlotContext, len(tally.EncryptedSums))
	for slot := range out {
		out[slot] = threshold.SlotContext{ElectionID: "test-election", SlotIndex: uint32(slot), TallyDigest: digest}
	}
	return out
}

// decryptFixture is a 5-of-9 DKG, a 3-party tally of five ballots, and the
// partials of trustees 1, 3, 5, 7 and 9 for every slot.
type decryptFixture struct {
	dkg      *threshold.DKGResult
	tally    *TallyResult
	contexts []threshold.SlotContext
	keys     map[int]*ristretto255.Element
	indices  []int
	partials map[int][]*threshold.Partial
}

func newDecryptFixture(t *testing.T) *decryptFixture {
	t.Helper()
	dkg, err := threshold.RunDKG(5, 9)
	if err != nil {
		t.Fatal(err)
	}
	votes := []int{0, 0, 1, 2, 2} // 2 for party 0, 1 for party 1, 2 for party 2
	tally, err := ComputeTally(encodeBallots(t, dkg.ElectionPublicKey, 3, votes))
	if err != nil {
		t.Fatalf("tally: %v", err)
	}
	f := &decryptFixture{
		dkg:      dkg,
		tally:    tally,
		contexts: tallyContexts(tally),
		keys:     make(map[int]*ristretto255.Element, len(dkg.Participants)),
		indices:  []int{1, 3, 5, 7, 9},
		partials: make(map[int][]*threshold.Partial),
	}
	for _, p := range dkg.Participants {
		f.keys[p.ID] = p.VerificationKey
	}
	for _, idx := range f.indices {
		f.partials[idx] = f.trusteePartials(t, idx, f.contexts)
	}
	return f
}

// trusteePartials is trustee idx's partial of every slot under contexts.
func (f *decryptFixture) trusteePartials(t *testing.T, idx int, contexts []threshold.SlotContext) []*threshold.Partial {
	t.Helper()
	share := f.dkg.Participants[idx-1].CombinedShare
	out := make([]*threshold.Partial, len(f.tally.EncryptedSums))
	for slot, ct := range f.tally.EncryptedSums {
		p, err := threshold.PartialDecrypt(contexts[slot], idx, share, ct)
		if err != nil {
			t.Fatalf("trustee %d slot %d: PartialDecrypt: %v", idx, slot, err)
		}
		out[slot] = p
	}
	return out
}

// copyPartials returns a shallow copy of partials that a subtest can change.
func (f *decryptFixture) copyPartials() map[int][]*threshold.Partial {
	out := make(map[int][]*threshold.Partial, len(f.partials))
	for idx, ps := range f.partials {
		out[idx] = ps
	}
	return out
}

func TestComputeTally(t *testing.T) {
	// Setup: DKG + encrypt ballots + tally
	f := newDecryptFixture(t)
	if f.tally.NumBallots != 5 {
		t.Fatalf("expected 5 ballots, got %d", f.tally.NumBallots)
	}

	// Decrypt with threshold
	expected := []int{2, 1, 2}
	results, err := DecryptTally(f.tally, f.contexts, f.partials, f.indices, f.keys, 5)
	if err != nil {
		t.Fatalf("DecryptTally: %v", err)
	}
	if len(results) != len(expected) {
		t.Fatalf("expected %d results, got %d", len(expected), len(results))
	}
	for i := range expected {
		if results[i] != expected[i] {
			t.Fatalf("party %d: expected %d, got %d", i, expected[i], results[i])
		}
	}
}

func TestComputeTallyEmpty(t *testing.T) {
	_, err := ComputeTally(nil)
	if err == nil {
		t.Fatal("should error on empty input")
	}
}

// TestComputeTallyRejectsMalformedCiphertexts: every ciphertext is decoded
// with encoding/hex and elgamal.CiphertextFromBytes, so a malformed entry is
// an error, never a panic or an undecoded ciphertext in the sums.
func TestComputeTallyRejectsMalformedCiphertexts(t *testing.T) {
	cases := map[string]string{
		"odd-length hex": "abc",
		"not hex":        strings.Repeat("zz", 64),
		"short":          strings.Repeat("ab", 32),
		"identity c1/c2": strings.Repeat("00", 64),
	}
	for name, ctHex := range cases {
		t.Run(name, func(t *testing.T) {
			encBallot, _ := json.Marshal(BallotData{PartyVector: []string{ctHex}})
			_, err := ComputeTally([]SerializedBallot{{BallotID: "b", EncryptedBallot: encBallot}})
			if err == nil {
				t.Fatalf("ComputeTally accepted ciphertext %q", ctHex)
			}
		})
	}
}

// TestDecryptTallyRejects: DecryptTally fails rather than return a result
// for inconsistent inputs or any partial that does not verify.
func TestDecryptTallyRejects(t *testing.T) {
	f := newDecryptFixture(t)

	t.Run("partial bound to another tally", func(t *testing.T) {
		otherDigest := threshold.TallyDigest(f.tally.EncryptedSums[:2])
		other := make([]threshold.SlotContext, len(f.contexts))
		for slot, sc := range f.contexts {
			sc.TallyDigest = otherDigest
			other[slot] = sc
		}
		partials := f.copyPartials()
		partials[5] = f.trusteePartials(t, 5, other)
		_, err := DecryptTally(f.tally, f.contexts, partials, f.indices, f.keys, 5)
		if !errors.Is(err, proof.ErrInvalidProof) {
			t.Fatalf("err = %v, want proof.ErrInvalidProof", err)
		}
	})

	t.Run("missing slot partial", func(t *testing.T) {
		partials := f.copyPartials()
		partials[7] = partials[7][:2]
		if _, err := DecryptTally(f.tally, f.contexts, partials, f.indices, f.keys, 5); err == nil {
			t.Fatal("DecryptTally accepted a trustee with a missing slot partial")
		}
	})

	t.Run("missing trustee", func(t *testing.T) {
		partials := f.copyPartials()
		delete(partials, 9)
		if _, err := DecryptTally(f.tally, f.contexts, partials, f.indices, f.keys, 5); err == nil {
			t.Fatal("DecryptTally accepted a listed trustee with no partials")
		}
	})

	t.Run("partials stored under another trustee", func(t *testing.T) {
		partials := f.copyPartials()
		partials[1] = partials[3]
		if _, err := DecryptTally(f.tally, f.contexts, partials, f.indices, f.keys, 5); err == nil {
			t.Fatal("DecryptTally accepted trustee 3's partials stored as trustee 1's")
		}
	})

	t.Run("fewer trustees than the threshold", func(t *testing.T) {
		if _, err := DecryptTally(f.tally, f.contexts, f.partials, f.indices[:4], f.keys, 5); err == nil {
			t.Fatal("DecryptTally accepted 4 trustees for threshold 5")
		}
	})

	t.Run("context count differs from slot count", func(t *testing.T) {
		if _, err := DecryptTally(f.tally, f.contexts[:2], f.partials, f.indices, f.keys, 5); err == nil {
			t.Fatal("DecryptTally accepted 2 contexts for 3 slots")
		}
	})

	t.Run("contexts out of slot order", func(t *testing.T) {
		swapped := []threshold.SlotContext{f.contexts[1], f.contexts[0], f.contexts[2]}
		if _, err := DecryptTally(f.tally, swapped, f.partials, f.indices, f.keys, 5); err == nil {
			t.Fatal("DecryptTally accepted contexts out of slot order")
		}
	})

	t.Run("nil tally", func(t *testing.T) {
		if _, err := DecryptTally(nil, f.contexts, f.partials, f.indices, f.keys, 5); err == nil {
			t.Fatal("DecryptTally accepted a nil tally")
		}
	})
}
