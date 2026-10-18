package ceremony

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/threshold"
)

// SerializedBallot represents a ballot as stored on the bulletin board.
type SerializedBallot struct {
	BallotID        string          `json:"ballot_id"`
	EncryptedBallot json.RawMessage `json:"encrypted_ballot"`
}

// BallotData is the deserialized encrypted ballot.
type BallotData struct {
	PartyVector []string `json:"party_vector"` // hex-encoded ciphertexts (64 bytes each)
}

// TallyResult holds the encrypted tally (one ciphertext per party).
type TallyResult struct {
	EncryptedSums []*elgamal.Ciphertext
	NumBallots    int
	NumParties    int
}

// ComputeTally performs homomorphic tallying over a set of encrypted ballots.
// Each ballot's party vector ciphertexts are multiplied element-wise.
func ComputeTally(ballots []SerializedBallot) (*TallyResult, error) {
	if len(ballots) == 0 {
		return nil, fmt.Errorf("no ballots to tally")
	}

	// Parse first ballot to determine dimensions
	var first BallotData
	if err := json.Unmarshal(ballots[0].EncryptedBallot, &first); err != nil {
		return nil, fmt.Errorf("parse first ballot: %w", err)
	}
	numParties := len(first.PartyVector)

	// Initialize accumulators
	sums := make([]*elgamal.Ciphertext, numParties)

	for i, sb := range ballots {
		var bd BallotData
		if err := json.Unmarshal(sb.EncryptedBallot, &bd); err != nil {
			return nil, fmt.Errorf("parse ballot %d: %w", i, err)
		}
		if len(bd.PartyVector) != numParties {
			return nil, fmt.Errorf("ballot %d has %d parties, expected %d", i, len(bd.PartyVector), numParties)
		}

		for j, ctHex := range bd.PartyVector {
			ct, err := ciphertextFromHex(ctHex)
			if err != nil {
				return nil, fmt.Errorf("ballot %d party %d: %w", i, j, err)
			}
			if sums[j] == nil {
				sums[j] = ct
			} else {
				sums[j] = elgamal.HomomorphicAdd(sums[j], ct)
			}
		}
	}

	return &TallyResult{
		EncryptedSums: sums,
		NumBallots:    len(ballots),
		NumParties:    numParties,
	}, nil
}

// ciphertextFromHex decodes one hex-encoded 64-byte ciphertext through
// elgamal.CiphertextFromBytes, so both halves are canonical, non-identity
// elements.
func ciphertextFromHex(s string) (*elgamal.Ciphertext, error) {
	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext hex: %w", err)
	}
	return elgamal.CiphertextFromBytes(data)
}

// DecryptTally decrypts every slot of tally with threshold.Combine, which
// re-verifies each partial's proof before combining. contexts[slot] is the
// slot context built from tally.EncryptedSums; partials maps a trustee index
// to that trustee's partials in slot order; trustees lists the quorum
// trustee indices whose partials are combined (the first quorum entries of
// the ceremony's trustee order); keys maps a trustee index to its
// verification key. It returns the plaintext vote count of every slot.
func DecryptTally(tally *TallyResult, contexts []threshold.SlotContext, partials map[int][]*threshold.Partial, trustees []int, keys map[int]*ristretto255.Element, quorum int) ([]int, error) {
	if tally == nil {
		return nil, errors.New("decrypt tally: nil tally")
	}
	if len(contexts) != len(tally.EncryptedSums) {
		return nil, fmt.Errorf("decrypt tally: %d slot contexts for %d slots", len(contexts), len(tally.EncryptedSums))
	}
	if len(trustees) != quorum {
		return nil, fmt.Errorf("decrypt tally: %d trustees for threshold %d", len(trustees), quorum)
	}

	results := make([]int, len(tally.EncryptedSums))
	for slot, ct := range tally.EncryptedSums {
		if contexts[slot].SlotIndex != uint32(slot) {
			return nil, fmt.Errorf("decrypt tally: context %d has slot index %d", slot, contexts[slot].SlotIndex)
		}
		slotPartials := make([]*threshold.Partial, len(trustees))
		for j, tidx := range trustees {
			tp := partials[tidx]
			if slot >= len(tp) || tp[slot] == nil {
				return nil, fmt.Errorf("decrypt tally: missing partial decryption from trustee %d for party %d", tidx, slot)
			}
			if tp[slot].TrusteeIndex != tidx {
				return nil, fmt.Errorf("decrypt tally: partial stored for trustee %d carries trustee index %d", tidx, tp[slot].TrusteeIndex)
			}
			slotPartials[j] = tp[slot]
		}

		m, err := threshold.Combine(contexts[slot], ct, slotPartials, keys, quorum, elgamal.MaxDecrypt)
		if err != nil {
			return nil, fmt.Errorf("decrypt tally: party %d: %w", slot, err)
		}
		results[slot] = m
	}

	return results, nil
}
