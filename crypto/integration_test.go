package crypto_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/gtank/ristretto255"

	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
	"github.com/valy0/otvoren-vot/crypto/merkle"
	"github.com/valy0/otvoren-vot/crypto/proof"
	"github.com/valy0/otvoren-vot/crypto/threshold"
)

func TestFullElectionSimulation(t *testing.T) {
	const (
		numTrustees = 9
		thresh      = 5
		numParties  = 5
		numVoters   = 20
		electionID  = "integration-election-2027"
	)

	// === PHASE 1: DKG ===
	t.Log("Phase 1: Distributed Key Generation")
	dkg, err := threshold.RunDKG(thresh, numTrustees)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	electionPK := dkg.ElectionPublicKey
	t.Logf("  Election public key generated (9 trustees, 5-of-9 threshold)")

	// === PHASE 2: VOTING ===
	t.Log("Phase 2: Voting")
	tree := merkle.New()
	ballots := make([]*elgamal.Ballot, numVoters)
	expectedTally := make([]int, numParties)

	for i := range numVoters {
		party := i % numParties
		expectedTally[party]++

		// Encode ballot
		var err error
		ballots[i], err = elgamal.EncodeBallot(electionPK, numParties, party)
		if err != nil {
			t.Fatalf("voter %d: EncodeBallot: %v", i, err)
		}
		idHash := sha256.Sum256([]byte{byte(i)})
		ctx := proof.Context{
			ElectionID: electionID,
			BallotID:   base64.RawURLEncoding.EncodeToString(idHash[:]),
		}

		// Verify binary proofs for each party element
		for j := range numParties {
			m := 0
			if j == party {
				m = 1
			}
			ctx.Index = uint32(j)
			bp, err := proof.ProveBinary(ctx, electionPK, ballots[i].PartyVector[j], m, ballots[i].PartyRandomness[j])
			if err != nil {
				t.Fatalf("voter %d, party %d: ProveBinary: %v", i, j, err)
			}
			if err := proof.VerifyBinary(ctx, electionPK, ballots[i].PartyVector[j], bp); err != nil {
				t.Fatalf("voter %d, party %d: binary proof failed: %v", i, j, err)
			}
		}

		// Verify sum-to-one proof
		rSum := internal.SumScalars(ballots[i].PartyRandomness)
		ctx.Index = numParties
		sp, err := proof.ProveSumOne(ctx, electionPK, ballots[i].PartyVector, rSum)
		if err != nil {
			t.Fatalf("voter %d: ProveSumOne: %v", i, err)
		}
		if err := proof.VerifySumOne(ctx, electionPK, ballots[i].PartyVector, sp); err != nil {
			t.Fatalf("voter %d: sum-to-one proof failed: %v", i, err)
		}

		// Append to Merkle tree (using ballot index as simplified ID)
		tree.Append(ballots[i].PartyVector[0].Bytes()) // use first ciphertext as leaf data
	}
	t.Logf("  %d voters cast ballots, all proofs verified", numVoters)

	// === PHASE 3: MERKLE VERIFICATION ===
	t.Log("Phase 3: Merkle Tree Verification")
	for i := range numVoters {
		p, err := tree.InclusionProof(i)
		if err != nil {
			t.Fatalf("voter %d: Merkle proof error: %v", i, err)
		}
		if !merkle.VerifyInclusion(tree.Root(), ballots[i].PartyVector[0].Bytes(), i, tree.Size(), p) {
			t.Fatalf("voter %d: Merkle inclusion failed", i)
		}
	}
	t.Logf("  All %d inclusion proofs verified", numVoters)

	// === PHASE 4: HOMOMORPHIC TALLYING ===
	t.Log("Phase 4: Homomorphic Tallying")
	tally, err := elgamal.TallyBallots(ballots)
	if err != nil {
		t.Fatalf("TallyBallots: %v", err)
	}
	t.Logf("  Tally computed (element-wise multiplication of %d ballots)", numVoters)

	// === PHASE 5: THRESHOLD DECRYPTION ===
	t.Log("Phase 5: Threshold Decryption (5-of-9 trustees)")
	trusteeIndices := []int{1, 3, 5, 7, 9} // arbitrary subset of 5

	keys := make(map[int]*ristretto255.Element, numTrustees)
	for _, p := range dkg.Participants {
		keys[p.ID] = p.VerificationKey
	}
	tallyDigest := threshold.TallyDigest(tally.PartyVector)

	for partyIdx := range numParties {
		sc := threshold.SlotContext{
			ElectionID:  electionID,
			SlotIndex:   uint32(partyIdx),
			TallyDigest: tallyDigest,
		}
		partials := make([]*threshold.Partial, thresh)
		for i, idx := range trusteeIndices {
			p := dkg.Participants[idx-1]
			partials[i], err = threshold.PartialDecrypt(sc, p.ID, p.CombinedShare, tally.PartyVector[partyIdx])
			if err != nil {
				t.Fatalf("party %d, trustee %d: PartialDecrypt: %v", partyIdx, idx, err)
			}
			// Verify each trustee's proof
			if err := threshold.VerifyPartial(sc, tally.PartyVector[partyIdx], partials[i], p.VerificationKey); err != nil {
				t.Fatalf("party %d, trustee %d: partial decryption proof failed: %v", partyIdx, idx, err)
			}
		}

		result, err := threshold.Combine(sc, tally.PartyVector[partyIdx], partials, keys, thresh, 100)
		if err != nil {
			t.Fatalf("party %d: Combine: %v", partyIdx, err)
		}
		if result != expectedTally[partyIdx] {
			t.Fatalf("party %d: expected %d votes, got %d", partyIdx, expectedTally[partyIdx], result)
		}
	}
	t.Logf("  Results: %v (matches expected)", expectedTally)

	// === SUMMARY ===
	t.Log("=== Election simulation PASSED ===")
	t.Logf("  Trustees: %d (threshold %d)", numTrustees, thresh)
	t.Logf("  Parties: %d", numParties)
	t.Logf("  Voters: %d", numVoters)
	t.Logf("  Merkle tree size: %d leaves", tree.Size())
	t.Logf("  All ZK proofs verified (binary, sum-to-one, partial decryption)")
	t.Logf("  Tally correct: %v", expectedTally)
}
