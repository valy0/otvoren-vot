package elgamal

import (
	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

// Ballot represents an encrypted ballot with party and candidate vectors.
type Ballot struct {
	PartyVector      []*Ciphertext
	PartyRandomness  []*edwards25519.Scalar // randomness for each party ciphertext
	CandidateVectors [][]*Ciphertext
	CandRandomness   [][]*edwards25519.Scalar
	NumParties       int
	NumCandidates    int
}

// EncodeBallot creates an encrypted ballot with party selection only.
// Returns the ballot with randomness values for proof generation.
func EncodeBallot(publicKey *edwards25519.Point, numParties, partyChoice int) *Ballot {
	b := &Ballot{
		PartyVector:     make([]*Ciphertext, numParties),
		PartyRandomness: make([]*edwards25519.Scalar, numParties),
		NumParties:      numParties,
	}
	for i := range numParties {
		m := 0
		if i == partyChoice {
			m = 1
		}
		r := internal.RandomScalar()
		b.PartyVector[i] = EncryptWithRandomness(publicKey, m, r)
		b.PartyRandomness[i] = r
	}
	return b
}

// EncodeBallotWithCandidates creates an encrypted ballot with party and candidate selection.
// candidateChoice = -1 means no candidate preference.
func EncodeBallotWithCandidates(publicKey *edwards25519.Point, numParties, numCandidates, partyChoice, candidateChoice int) *Ballot {
	b := EncodeBallot(publicKey, numParties, partyChoice)
	b.NumCandidates = numCandidates
	b.CandidateVectors = make([][]*Ciphertext, numParties)
	b.CandRandomness = make([][]*edwards25519.Scalar, numParties)

	for p := range numParties {
		b.CandidateVectors[p] = make([]*Ciphertext, numCandidates)
		b.CandRandomness[p] = make([]*edwards25519.Scalar, numCandidates)
		for c := range numCandidates {
			m := 0
			if p == partyChoice && c == candidateChoice {
				m = 1
			}
			r := internal.RandomScalar()
			b.CandidateVectors[p][c] = EncryptWithRandomness(publicKey, m, r)
			b.CandRandomness[p][c] = r
		}
	}
	return b
}

// TallyBallots homomorphically sums a slice of ballots.
func TallyBallots(ballots []*Ballot) *Ballot {
	if len(ballots) == 0 {
		return nil
	}
	numParties := ballots[0].NumParties
	result := &Ballot{
		PartyVector: make([]*Ciphertext, numParties),
		NumParties:  numParties,
	}

	for i := range numParties {
		cts := make([]*Ciphertext, len(ballots))
		for j, b := range ballots {
			cts[j] = b.PartyVector[i]
		}
		result.PartyVector[i] = HomomorphicAdd(cts...)
	}

	if ballots[0].CandidateVectors != nil {
		numCand := ballots[0].NumCandidates
		result.NumCandidates = numCand
		result.CandidateVectors = make([][]*Ciphertext, numParties)
		for p := range numParties {
			result.CandidateVectors[p] = make([]*Ciphertext, numCand)
			for c := range numCand {
				cts := make([]*Ciphertext, len(ballots))
				for j, b := range ballots {
					cts[j] = b.CandidateVectors[p][c]
				}
				result.CandidateVectors[p][c] = HomomorphicAdd(cts...)
			}
		}
	}

	return result
}
