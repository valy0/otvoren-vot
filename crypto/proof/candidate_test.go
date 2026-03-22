package proof

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

// --- Candidate Sum Proofs ---

func TestProveCandidateSumZero(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	numCandidates := 4

	// All zeros — voter did not select any candidate in this party.
	cts := make([]*elgamal.Ciphertext, numCandidates)
	rs := make([]*edwards25519.Scalar, numCandidates)
	for i := range numCandidates {
		r := internal.RandomScalar()
		cts[i] = elgamal.EncryptWithRandomness(kp.PublicKey, 0, r)
		rs[i] = r
	}
	aggCt := elgamal.HomomorphicAdd(cts...)
	rSum := internal.SumScalars(rs)

	p := ProveCandidateSum(kp.PublicKey, aggCt, 0, rSum)
	if !VerifyCandidateSum(kp.PublicKey, aggCt, p) {
		t.Fatal("candidate sum=0 proof should verify")
	}
}

func TestProveCandidateSumOne(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	numCandidates := 4
	selected := 2

	cts := make([]*elgamal.Ciphertext, numCandidates)
	rs := make([]*edwards25519.Scalar, numCandidates)
	for i := range numCandidates {
		m := 0
		if i == selected {
			m = 1
		}
		r := internal.RandomScalar()
		cts[i] = elgamal.EncryptWithRandomness(kp.PublicKey, m, r)
		rs[i] = r
	}
	aggCt := elgamal.HomomorphicAdd(cts...)
	rSum := internal.SumScalars(rs)

	p := ProveCandidateSum(kp.PublicKey, aggCt, 1, rSum)
	if !VerifyCandidateSum(kp.PublicKey, aggCt, p) {
		t.Fatal("candidate sum=1 proof should verify")
	}
}

func TestVerifyCandidateSumRejectsTwo(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	numCandidates := 4

	// Two candidates selected — sum is 2, which is invalid.
	cts := make([]*elgamal.Ciphertext, numCandidates)
	rs := make([]*edwards25519.Scalar, numCandidates)
	for i := range numCandidates {
		m := 0
		if i < 2 {
			m = 1
		}
		r := internal.RandomScalar()
		cts[i] = elgamal.EncryptWithRandomness(kp.PublicKey, m, r)
		rs[i] = r
	}
	aggCt := elgamal.HomomorphicAdd(cts...)
	rSum := internal.SumScalars(rs)

	// Prover tries to claim sum=1 but actual sum is 2 — proof should fail.
	p := ProveCandidateSum(kp.PublicKey, aggCt, 1, rSum)
	if VerifyCandidateSum(kp.PublicKey, aggCt, p) {
		t.Fatal("candidate sum=2 claimed as 1 should NOT verify")
	}
}

func TestCandidateSumDomainSeparation(t *testing.T) {
	// A candidate sum proof must not verify as a plain binary proof,
	// because the domain separators differ.
	kp := elgamal.GenerateKeyPair()
	r := internal.RandomScalar()
	ct := elgamal.EncryptWithRandomness(kp.PublicKey, 1, r)

	candidateProof := ProveCandidateSum(kp.PublicKey, ct, 1, r)
	if VerifyBinary(kp.PublicKey, ct, candidateProof) {
		t.Fatal("candidate sum proof should NOT verify as binary proof (different domain)")
	}
}

// --- Consistency Proofs ---

func TestProveConsistencyPartySelectedWithCandidate(t *testing.T) {
	// party=1, candidate_sum=1 => diff=0
	kp := elgamal.GenerateKeyPair()
	rParty := internal.RandomScalar()
	partyCt := elgamal.EncryptWithRandomness(kp.PublicKey, 1, rParty)

	numCandidates := 3
	candCts := make([]*elgamal.Ciphertext, numCandidates)
	candRs := make([]*edwards25519.Scalar, numCandidates)
	for i := range numCandidates {
		m := 0
		if i == 1 {
			m = 1
		}
		r := internal.RandomScalar()
		candCts[i] = elgamal.EncryptWithRandomness(kp.PublicKey, m, r)
		candRs[i] = r
	}
	candSumCt := elgamal.HomomorphicAdd(candCts...)
	rCandSum := internal.SumScalars(candRs)

	rDiff := new(edwards25519.Scalar).Subtract(rParty, rCandSum)
	p := ProveConsistency(kp.PublicKey, partyCt, candSumCt, 0, rDiff)
	if !VerifyConsistency(kp.PublicKey, partyCt, candSumCt, p) {
		t.Fatal("consistency proof (party=1, cand_sum=1, diff=0) should verify")
	}
}

func TestProveConsistencyPartySelectedNoCandidate(t *testing.T) {
	// party=1, candidate_sum=0 => diff=1
	kp := elgamal.GenerateKeyPair()
	rParty := internal.RandomScalar()
	partyCt := elgamal.EncryptWithRandomness(kp.PublicKey, 1, rParty)

	numCandidates := 3
	candCts := make([]*elgamal.Ciphertext, numCandidates)
	candRs := make([]*edwards25519.Scalar, numCandidates)
	for i := range numCandidates {
		r := internal.RandomScalar()
		candCts[i] = elgamal.EncryptWithRandomness(kp.PublicKey, 0, r)
		candRs[i] = r
	}
	candSumCt := elgamal.HomomorphicAdd(candCts...)
	rCandSum := internal.SumScalars(candRs)

	rDiff := new(edwards25519.Scalar).Subtract(rParty, rCandSum)
	p := ProveConsistency(kp.PublicKey, partyCt, candSumCt, 1, rDiff)
	if !VerifyConsistency(kp.PublicKey, partyCt, candSumCt, p) {
		t.Fatal("consistency proof (party=1, cand_sum=0, diff=1) should verify")
	}
}

func TestProveConsistencyPartyNotSelectedNoCandidate(t *testing.T) {
	// party=0, candidate_sum=0 => diff=0
	kp := elgamal.GenerateKeyPair()
	rParty := internal.RandomScalar()
	partyCt := elgamal.EncryptWithRandomness(kp.PublicKey, 0, rParty)

	numCandidates := 3
	candCts := make([]*elgamal.Ciphertext, numCandidates)
	candRs := make([]*edwards25519.Scalar, numCandidates)
	for i := range numCandidates {
		r := internal.RandomScalar()
		candCts[i] = elgamal.EncryptWithRandomness(kp.PublicKey, 0, r)
		candRs[i] = r
	}
	candSumCt := elgamal.HomomorphicAdd(candCts...)
	rCandSum := internal.SumScalars(candRs)

	rDiff := new(edwards25519.Scalar).Subtract(rParty, rCandSum)
	p := ProveConsistency(kp.PublicKey, partyCt, candSumCt, 0, rDiff)
	if !VerifyConsistency(kp.PublicKey, partyCt, candSumCt, p) {
		t.Fatal("consistency proof (party=0, cand_sum=0, diff=0) should verify")
	}
}

func TestVerifyConsistencyRejectsPartyNotSelectedWithCandidate(t *testing.T) {
	// party=0, candidate_sum=1 => diff = -1 mod q, which is NOT in {0, 1}.
	// The binary proof will be invalid because the prover cannot honestly
	// prove -1 is 0 or 1.
	kp := elgamal.GenerateKeyPair()
	rParty := internal.RandomScalar()
	partyCt := elgamal.EncryptWithRandomness(kp.PublicKey, 0, rParty)

	numCandidates := 3
	candCts := make([]*elgamal.Ciphertext, numCandidates)
	candRs := make([]*edwards25519.Scalar, numCandidates)
	for i := range numCandidates {
		m := 0
		if i == 0 {
			m = 1
		}
		r := internal.RandomScalar()
		candCts[i] = elgamal.EncryptWithRandomness(kp.PublicKey, m, r)
		candRs[i] = r
	}
	candSumCt := elgamal.HomomorphicAdd(candCts...)
	rCandSum := internal.SumScalars(candRs)
	rDiff := new(edwards25519.Scalar).Subtract(rParty, rCandSum)

	// Prover tries to claim diff=0, but actual diff is -1 mod q.
	p := ProveConsistency(kp.PublicKey, partyCt, candSumCt, 0, rDiff)
	if VerifyConsistency(kp.PublicKey, partyCt, candSumCt, p) {
		t.Fatal("consistency proof for party=0, cand_sum=1 should NOT verify")
	}
}

// --- Full Ballot Proof Set ---

func TestFullBallotProofSet(t *testing.T) {
	// 3 parties, 2 candidates per party.
	// Party 1 selected, candidate 0 of party 1 selected.
	numParties := 3
	numCandidates := 2
	partyChoice := 1
	candidateChoice := 0

	kp := elgamal.GenerateKeyPair()
	ballot := elgamal.EncodeBallotWithCandidates(kp.PublicKey, numParties, numCandidates, partyChoice, candidateChoice)

	// --- Proof 1: Binary proofs for each party element ---
	for i := range numParties {
		m := 0
		if i == partyChoice {
			m = 1
		}
		bp := ProveBinary(kp.PublicKey, ballot.PartyVector[i], m, ballot.PartyRandomness[i])
		if !VerifyBinary(kp.PublicKey, ballot.PartyVector[i], bp) {
			t.Fatalf("party binary proof %d should verify", i)
		}
	}

	// --- Proof 2: Party vector sums to 1 ---
	partyRSum := internal.SumScalars(ballot.PartyRandomness)
	sumProof := ProveSumOne(kp.PublicKey, ballot.PartyVector, partyRSum)
	if !VerifySumOne(kp.PublicKey, ballot.PartyVector, sumProof) {
		t.Fatal("party sum proof should verify")
	}

	// --- Proof 3: Binary proofs for each candidate element ---
	for p := range numParties {
		for c := range numCandidates {
			m := 0
			if p == partyChoice && c == candidateChoice {
				m = 1
			}
			bp := ProveBinary(kp.PublicKey, ballot.CandidateVectors[p][c], m, ballot.CandRandomness[p][c])
			if !VerifyBinary(kp.PublicKey, ballot.CandidateVectors[p][c], bp) {
				t.Fatalf("candidate binary proof [%d][%d] should verify", p, c)
			}
		}
	}

	// --- Proof 4 & 5: Candidate sum and consistency per party ---
	for p := range numParties {
		// Candidate sum for this party.
		candSum := 0
		if p == partyChoice && candidateChoice >= 0 {
			candSum = 1
		}

		aggCt := elgamal.HomomorphicAdd(ballot.CandidateVectors[p]...)
		rCandSum := internal.SumScalars(ballot.CandRandomness[p])

		// Proof 4: Candidate sum ∈ {0, 1}
		csProof := ProveCandidateSum(kp.PublicKey, aggCt, candSum, rCandSum)
		if !VerifyCandidateSum(kp.PublicKey, aggCt, csProof) {
			t.Fatalf("candidate sum proof for party %d should verify", p)
		}

		// Proof 5: Consistency — diff = partyBit - candSum ∈ {0, 1}
		partyBit := 0
		if p == partyChoice {
			partyBit = 1
		}
		diff := partyBit - candSum

		rDiff := new(edwards25519.Scalar).Subtract(ballot.PartyRandomness[p], rCandSum)
		conProof := ProveConsistency(kp.PublicKey, ballot.PartyVector[p], aggCt, diff, rDiff)
		if !VerifyConsistency(kp.PublicKey, ballot.PartyVector[p], aggCt, conProof) {
			t.Fatalf("consistency proof for party %d should verify", p)
		}
	}
}

func TestFullBallotProofSetNoCandidate(t *testing.T) {
	// Party selected but no candidate preference.
	numParties := 3
	numCandidates := 2
	partyChoice := 0
	candidateChoice := -1 // no candidate

	kp := elgamal.GenerateKeyPair()
	ballot := elgamal.EncodeBallotWithCandidates(kp.PublicKey, numParties, numCandidates, partyChoice, candidateChoice)

	// Verify all 5 proof types.
	for i := range numParties {
		m := 0
		if i == partyChoice {
			m = 1
		}
		bp := ProveBinary(kp.PublicKey, ballot.PartyVector[i], m, ballot.PartyRandomness[i])
		if !VerifyBinary(kp.PublicKey, ballot.PartyVector[i], bp) {
			t.Fatalf("party binary proof %d should verify", i)
		}
	}

	partyRSum := internal.SumScalars(ballot.PartyRandomness)
	sumProof := ProveSumOne(kp.PublicKey, ballot.PartyVector, partyRSum)
	if !VerifySumOne(kp.PublicKey, ballot.PartyVector, sumProof) {
		t.Fatal("party sum proof should verify")
	}

	for p := range numParties {
		for c := range numCandidates {
			bp := ProveBinary(kp.PublicKey, ballot.CandidateVectors[p][c], 0, ballot.CandRandomness[p][c])
			if !VerifyBinary(kp.PublicKey, ballot.CandidateVectors[p][c], bp) {
				t.Fatalf("candidate binary proof [%d][%d] should verify", p, c)
			}
		}
	}

	for p := range numParties {
		aggCt := elgamal.HomomorphicAdd(ballot.CandidateVectors[p]...)
		rCandSum := internal.SumScalars(ballot.CandRandomness[p])

		// All candidate sums are 0 (no preference anywhere).
		csProof := ProveCandidateSum(kp.PublicKey, aggCt, 0, rCandSum)
		if !VerifyCandidateSum(kp.PublicKey, aggCt, csProof) {
			t.Fatalf("candidate sum proof for party %d should verify", p)
		}

		// diff = partyBit - 0
		partyBit := 0
		if p == partyChoice {
			partyBit = 1
		}

		rDiff := new(edwards25519.Scalar).Subtract(ballot.PartyRandomness[p], rCandSum)
		conProof := ProveConsistency(kp.PublicKey, ballot.PartyVector[p], aggCt, partyBit, rDiff)
		if !VerifyConsistency(kp.PublicKey, ballot.PartyVector[p], aggCt, conProof) {
			t.Fatalf("consistency proof for party %d should verify", p)
		}
	}
}
