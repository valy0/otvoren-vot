package threshold

import (
	"fmt"

	"github.com/gtank/ristretto255"
)

// DKGParticipant represents one trustee in the DKG protocol.
type DKGParticipant struct {
	ID              int // 1-based Shamir index
	dealer          *Dealer
	receivedShares  []*ristretto255.Scalar // shares received from other participants
	CombinedShare   *ristretto255.Scalar   // final combined share
	VerificationKey *ristretto255.Element  // CombinedShare * G
}

// DKGResult holds the output of a completed DKG.
type DKGResult struct {
	ElectionPublicKey *ristretto255.Element
	Participants      []*DKGParticipant
}

// RunDKG executes a full DKG protocol among numParties participants with the
// given threshold, which must satisfy 1 <= threshold <= numParties.
// In production, each participant runs on a separate HSM. This function
// simulates the full protocol locally for testing and development.
func RunDKG(threshold, numParties int) (*DKGResult, error) {
	if err := checkThreshold(threshold, numParties); err != nil {
		return nil, err
	}

	// Round 1: Each participant generates a polynomial and publishes commitments
	participants := make([]*DKGParticipant, numParties)
	for i := range numParties {
		dealer, err := NewDealer(threshold, numParties)
		if err != nil {
			return nil, fmt.Errorf("participant %d: %w", i+1, err)
		}
		participants[i] = &DKGParticipant{
			ID:             i + 1,
			dealer:         dealer,
			receivedShares: make([]*ristretto255.Scalar, numParties),
		}
	}
	// Round 2: Each participant distributes shares and verifies received shares
	for i, pi := range participants {
		for j, pj := range participants {
			// Participant j sends share f_j(i+1) to participant i
			share := pj.dealer.Shares[i]

			// Participant i verifies the share against j's commitments
			if !VerifyShare(share, i+1, threshold, pj.dealer.Commitments) {
				return nil, fmt.Errorf("participant %d: invalid share from participant %d", i+1, j+1)
			}

			pi.receivedShares[j] = share
		}
	}

	// Round 3: Each participant combines received shares
	for _, p := range participants {
		p.CombinedShare = ristretto255.NewScalar()
		for _, share := range p.receivedShares {
			p.CombinedShare.Add(p.CombinedShare, share)
		}
		p.VerificationKey = ristretto255.NewIdentityElement().ScalarBaseMult(p.CombinedShare)
	}

	// Compute the election public key: sum of all dealers' first commitments
	electionPK := ristretto255.NewIdentityElement()
	for _, p := range participants {
		electionPK.Add(electionPK, p.dealer.PublicKey())
	}

	return &DKGResult{
		ElectionPublicKey: electionPK,
		Participants:      participants,
	}, nil
}
