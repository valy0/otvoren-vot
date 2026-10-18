package elgamal

import (
	"errors"
	"fmt"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

var (
	// ErrShapeMismatch is returned when ballots do not share the same shape.
	ErrShapeMismatch = errors.New("elgamal: ballot shape mismatch")
	// ErrNoBallots is returned when there are no ballots to tally.
	ErrNoBallots = errors.New("elgamal: no ballots")
)

// Ballot represents an encrypted ballot with party and candidate vectors.
type Ballot struct {
	PartyVector      []*Ciphertext
	PartyRandomness  []*ristretto255.Scalar // randomness for each party ciphertext
	CandidateVectors [][]*Ciphertext
	CandRandomness   [][]*ristretto255.Scalar
	NumParties       int
	NumCandidates    int
}

// EncodeBallot creates an encrypted ballot with party selection only.
// Returns the ballot with randomness values for proof generation.
func EncodeBallot(publicKey *ristretto255.Element, numParties, partyChoice int) (*Ballot, error) {
	b := &Ballot{
		PartyVector:     make([]*Ciphertext, numParties),
		PartyRandomness: make([]*ristretto255.Scalar, numParties),
		NumParties:      numParties,
	}
	for i := range numParties {
		m := 0
		if i == partyChoice {
			m = 1
		}
		r := internal.RandomScalar()
		ct, err := EncryptWithRandomness(publicKey, m, r)
		if err != nil {
			return nil, fmt.Errorf("party %d: %w", i, err)
		}
		b.PartyVector[i] = ct
		b.PartyRandomness[i] = r
	}
	return b, nil
}

// EncodeBallotWithCandidates creates an encrypted ballot with party and candidate selection.
// candidateChoice = -1 means no candidate preference.
func EncodeBallotWithCandidates(publicKey *ristretto255.Element, numParties, numCandidates, partyChoice, candidateChoice int) (*Ballot, error) {
	b, err := EncodeBallot(publicKey, numParties, partyChoice)
	if err != nil {
		return nil, err
	}
	b.NumCandidates = numCandidates
	b.CandidateVectors = make([][]*Ciphertext, numParties)
	b.CandRandomness = make([][]*ristretto255.Scalar, numParties)

	for p := range numParties {
		b.CandidateVectors[p] = make([]*Ciphertext, numCandidates)
		b.CandRandomness[p] = make([]*ristretto255.Scalar, numCandidates)
		for c := range numCandidates {
			m := 0
			if p == partyChoice && c == candidateChoice {
				m = 1
			}
			r := internal.RandomScalar()
			ct, err := EncryptWithRandomness(publicKey, m, r)
			if err != nil {
				return nil, fmt.Errorf("party %d candidate %d: %w", p, c, err)
			}
			b.CandidateVectors[p][c] = ct
			b.CandRandomness[p][c] = r
		}
	}
	return b, nil
}

// checkShape verifies that b has the same shape as the reference ballot ref.
// It validates the slices it will index, not just the declared counts.
func checkShape(ref, b *Ballot) error {
	if b == nil {
		return fmt.Errorf("%w: nil ballot", ErrShapeMismatch)
	}
	if b.NumParties != ref.NumParties || len(b.PartyVector) != ref.NumParties {
		return fmt.Errorf("%w: party vector length", ErrShapeMismatch)
	}
	if (b.CandidateVectors == nil) != (ref.CandidateVectors == nil) {
		return fmt.Errorf("%w: candidate vectors present on only one ballot", ErrShapeMismatch)
	}
	if ref.CandidateVectors == nil {
		return nil
	}
	if b.NumCandidates != ref.NumCandidates || len(b.CandidateVectors) != ref.NumParties {
		return fmt.Errorf("%w: candidate vector shape", ErrShapeMismatch)
	}
	for p := range b.CandidateVectors {
		if len(b.CandidateVectors[p]) != ref.NumCandidates {
			return fmt.Errorf("%w: candidate vector shape", ErrShapeMismatch)
		}
	}
	return nil
}

// TallyBallots homomorphically sums a slice of ballots. All ballots must have
// the same shape, otherwise ErrShapeMismatch is returned.
func TallyBallots(ballots []*Ballot) (*Ballot, error) {
	if len(ballots) == 0 {
		return nil, ErrNoBallots
	}
	first := ballots[0]
	if first == nil {
		return nil, fmt.Errorf("%w: nil ballot", ErrShapeMismatch)
	}
	if len(first.PartyVector) != first.NumParties {
		return nil, fmt.Errorf("%w: party vector length", ErrShapeMismatch)
	}
	if first.CandidateVectors != nil {
		if len(first.CandidateVectors) != first.NumParties {
			return nil, fmt.Errorf("%w: candidate vector shape", ErrShapeMismatch)
		}
		for p := range first.CandidateVectors {
			if len(first.CandidateVectors[p]) != first.NumCandidates {
				return nil, fmt.Errorf("%w: candidate vector shape", ErrShapeMismatch)
			}
		}
	}
	for i, b := range ballots {
		if err := checkShape(first, b); err != nil {
			return nil, fmt.Errorf("ballot %d: %w", i, err)
		}
	}

	numParties := first.NumParties
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

	if first.CandidateVectors != nil {
		numCand := first.NumCandidates
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

	return result, nil
}
