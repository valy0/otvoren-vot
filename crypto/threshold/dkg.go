package threshold

import (
	"fmt"

	"filippo.io/edwards25519"
)

// DKGParticipant represents one trustee in the DKG protocol.
type DKGParticipant struct {
	ID              int // 1-based
	dealer          *Dealer
	receivedShares  []*edwards25519.Scalar // shares received from other participants
	CombinedShare   *edwards25519.Scalar   // final combined share
	VerificationKey *edwards25519.Point    // g^{combined_share}
}

// DKGResult holds the output of a completed DKG.
type DKGResult struct {
	ElectionPublicKey *edwards25519.Point
	Participants      []*DKGParticipant
}

// RunDKG executes a full DKG protocol among numParties participants with the given threshold.
// In production, each participant runs on a separate HSM. This function simulates the full
// protocol locally for testing and development.
func RunDKG(threshold, numParties int) (*DKGResult, error) {
	if threshold > numParties {
		return nil, fmt.Errorf("threshold %d exceeds numParties %d", threshold, numParties)
	}

	// Round 1: Each participant generates a polynomial and publishes commitments
	participants := make([]*DKGParticipant, numParties)
	for i := range numParties {
		participants[i] = &DKGParticipant{
			ID:             i + 1,
			dealer:         NewDealer(threshold, numParties),
			receivedShares: make([]*edwards25519.Scalar, numParties),
		}
	}

	// Round 2: Each participant distributes shares and verifies received shares
	for i, pi := range participants {
		for j, pj := range participants {
			// Participant j sends share f_j(i+1) to participant i
			share := pj.dealer.Shares[i]

			// Participant i verifies the share against j's commitments
			if !VerifyShare(share, i+1, pj.dealer.Commitments) {
				return nil, fmt.Errorf("participant %d: invalid share from participant %d", i+1, j+1)
			}

			pi.receivedShares[j] = share
		}
	}

	// Round 3: Each participant combines received shares
	for _, p := range participants {
		p.CombinedShare = edwards25519.NewScalar()
		for _, share := range p.receivedShares {
			p.CombinedShare.Add(p.CombinedShare, share)
		}
		p.VerificationKey = new(edwards25519.Point).ScalarBaseMult(p.CombinedShare)
	}

	// Compute the election public key: product of all dealers' first commitments
	electionPK := edwards25519.NewIdentityPoint()
	for _, p := range participants {
		electionPK.Add(electionPK, p.dealer.PublicKey())
	}

	return &DKGResult{
		ElectionPublicKey: electionPK,
		Participants:      participants,
	}, nil
}
