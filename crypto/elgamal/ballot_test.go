package elgamal

import (
	"errors"
	"testing"
)

func TestEncodeBallotPartyOnly(t *testing.T) {
	kp := GenerateKeyPair()
	b, err := EncodeBallot(kp.PublicKey, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.PartyVector) != 5 {
		t.Fatalf("expected 5 party ciphertexts, got %d", len(b.PartyVector))
	}
	if len(b.PartyRandomness) != 5 {
		t.Fatal("should have 5 randomness values")
	}
	for i, ct := range b.PartyVector {
		m := Decrypt(kp.PrivateKey, ct)
		if i == 3 && m != 1 {
			t.Fatalf("party %d should be 1, got %d", i, m)
		}
		if i != 3 && m != 0 {
			t.Fatalf("party %d should be 0, got %d", i, m)
		}
	}
}

func TestEncodeBallotWithCandidates(t *testing.T) {
	kp := GenerateKeyPair()
	b, err := EncodeBallotWithCandidates(kp.PublicKey, 3, 4, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i, ct := range b.CandidateVectors[1] {
		m := Decrypt(kp.PrivateKey, ct)
		if i == 2 && m != 1 {
			t.Fatalf("candidate %d should be 1, got %d", i, m)
		}
		if i != 2 && m != 0 {
			t.Fatalf("candidate %d should be 0, got %d", i, m)
		}
	}
	// Other parties all zeros
	for i, ct := range b.CandidateVectors[0] {
		m := Decrypt(kp.PrivateKey, ct)
		if m != 0 {
			t.Fatalf("party 0 candidate %d should be 0, got %d", i, m)
		}
	}
}

func TestEncodeBallotRandomnessUsable(t *testing.T) {
	kp := GenerateKeyPair()
	b, err := EncodeBallot(kp.PublicKey, 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Verify randomness matches: re-encrypt with stored r should give same ciphertext
	for i := range 3 {
		m := 0
		if i == 1 {
			m = 1
		}
		ct2, err := EncryptWithRandomness(kp.PublicKey, m, b.PartyRandomness[i])
		if err != nil {
			t.Fatal(err)
		}
		if ct2.C1.Equal(b.PartyVector[i].C1) != 1 || ct2.C2.Equal(b.PartyVector[i].C2) != 1 {
			t.Fatalf("party %d: randomness should reproduce same ciphertext", i)
		}
	}
}

func TestHomomorphicBallotTally(t *testing.T) {
	kp := GenerateKeyPair()
	numParties := 3
	votes := []int{0, 0, 0, 0, 1, 1, 1, 2, 2, 2}
	ballots := make([]*Ballot, len(votes))
	for i, party := range votes {
		var err error
		ballots[i], err = EncodeBallot(kp.PublicKey, numParties, party)
		if err != nil {
			t.Fatal(err)
		}
	}
	tally, err := TallyBallots(ballots)
	if err != nil {
		t.Fatal(err)
	}
	expected := []int{4, 3, 3}
	for i, ct := range tally.PartyVector {
		m := Decrypt(kp.PrivateKey, ct)
		if m != expected[i] {
			t.Fatalf("party %d: expected %d, got %d", i, expected[i], m)
		}
	}
}

func TestTallyBallotsEmpty(t *testing.T) {
	result, err := TallyBallots(nil)
	if result != nil || !errors.Is(err, ErrNoBallots) {
		t.Fatal("TallyBallots(nil) should return nil and ErrNoBallots")
	}
}
