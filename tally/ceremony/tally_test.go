package ceremony

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/threshold"
)

func TestComputeTally(t *testing.T) {
	// Setup: DKG + encrypt ballots
	dkg, err := threshold.RunDKG(5, 9)
	if err != nil {
		t.Fatal(err)
	}

	numParties := 3
	votes := []int{0, 0, 1, 2, 2} // 2 for party 0, 1 for party 1, 2 for party 2

	ballots := make([]SerializedBallot, len(votes))
	for i, party := range votes {
		b := elgamal.EncodeBallot(dkg.ElectionPublicKey, numParties, party)
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

	tally, err := ComputeTally(ballots)
	if err != nil {
		t.Fatalf("tally: %v", err)
	}
	if tally.NumBallots != 5 {
		t.Fatalf("expected 5 ballots, got %d", tally.NumBallots)
	}

	// Decrypt with threshold
	indices := []int{1, 3, 5, 7, 9}
	expected := []int{2, 1, 2}

	for i, encSum := range tally.EncryptedSums {
		partials := make([]*threshold.PartialDecryption, 5)
		for j, idx := range indices {
			p := dkg.Participants[idx-1]
			partials[j] = threshold.PartialDecrypt(p.CombinedShare, encSum)
		}
		result := threshold.CombinePartials(encSum, partials, indices, 100)
		if result != expected[i] {
			t.Fatalf("party %d: expected %d, got %d", i, expected[i], result)
		}
	}
}

func TestComputeTallyEmpty(t *testing.T) {
	_, err := ComputeTally(nil)
	if err == nil {
		t.Fatal("should error on empty input")
	}
}
