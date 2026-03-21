package ceremony

import (
	"encoding/json"
	"fmt"

	"filippo.io/edwards25519"
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

func ciphertextFromHex(hex string) (*elgamal.Ciphertext, error) {
	data, err := hexDecode(hex)
	if err != nil {
		return nil, err
	}
	return elgamal.CiphertextFromBytes(data)
}

func hexDecode(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var v byte
		for j := 0; j < 2; j++ {
			c := s[i+j]
			switch {
			case c >= '0' && c <= '9':
				v = v*16 + c - '0'
			case c >= 'a' && c <= 'f':
				v = v*16 + c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v = v*16 + c - 'A' + 10
			default:
				return nil, fmt.Errorf("invalid hex char: %c", c)
			}
		}
		b[i/2] = v
	}
	return b, nil
}

// DecryptTally decrypts the tally result using threshold partial decryptions.
// Returns plaintext vote counts per party.
func DecryptTally(tally *TallyResult, partials []map[int]*PartialDecryptionData, trusteeIndices []int) ([]int, error) {
	results := make([]int, tally.NumParties)

	for i, encSum := range tally.EncryptedSums {
		// Collect partial decryptions for this party slot
		pds := make([]*threshold.PartialDecryption, len(trusteeIndices))
		for j := range trusteeIndices {
			pd := partials[j][i]
			if pd == nil {
				return nil, fmt.Errorf("missing partial decryption from trustee %d for party %d", trusteeIndices[j], i)
			}
			pds[j] = &threshold.PartialDecryption{D: pd.D}
		}

		result := threshold.CombinePartials(encSum, pds, trusteeIndices, elgamal.MaxDecrypt)
		if result == -1 {
			return nil, fmt.Errorf("BSGS failed for party %d", i)
		}
		results[i] = result
	}

	return results, nil
}

// PartialDecryptionData holds a parsed partial decryption.
type PartialDecryptionData struct {
	D *edwards25519.Point
}
