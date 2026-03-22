package gnark

import (
	"math/big"
	"sort"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// TestDeduplicationCircuit runs the full pipeline: build witness from random
// data, compile, setup, prove, verify. This is the happy-path integration test.
func TestDeduplicationCircuit(t *testing.T) {
	// 1. Generate 32 random ballot IDs (enough to fill a tree of depth 5 = 2^5).
	const totalBallots = 1 << TreeDepth // 32
	allIDs := make([]fr.Element, totalBallots)
	for i := range totalBallots {
		if _, err := allIDs[i].SetRandom(); err != nil {
			t.Fatalf("generating random ID %d: %v", i, err)
		}
	}

	// 2. Generate random ballot data for all 32.
	allBallots := make([][BallotFieldElems]fr.Element, totalBallots)
	for i := range totalBallots {
		for j := range BallotFieldElems {
			if _, err := allBallots[i][j].SetRandom(); err != nil {
				t.Fatalf("generating random ballot data [%d][%d]: %v", i, j, err)
			}
		}
	}

	// 3. Compute all ballot leaves: leaf = Poseidon2(ID, ballot[0..9]).
	allLeaves := make([]fr.Element, totalBallots)
	for i := range totalBallots {
		elems := make([]fr.Element, 1+BallotFieldElems)
		elems[0] = allIDs[i]
		copy(elems[1:], allBallots[i][:])
		allLeaves[i] = poseidon2Hash(elems...)
	}

	// 4. Pick 10 active ballots (BatchSize). Sort by ID ascending.
	type indexedID struct {
		origIdx int
		id      fr.Element
	}
	candidates := make([]indexedID, totalBallots)
	for i := range totalBallots {
		candidates[i] = indexedID{origIdx: i, id: allIDs[i]}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].id.Cmp(&candidates[j].id) < 0
	})
	// Take the first BatchSize after sorting to guarantee ascending order.
	active := candidates[:BatchSize]

	activeIndices := make([]int, BatchSize)
	activeIDs := make([]fr.Element, BatchSize)
	activeBallots := make([][BallotFieldElems]fr.Element, BatchSize)
	for i, c := range active {
		activeIndices[i] = c.origIdx
		activeIDs[i] = allIDs[c.origIdx]
		activeBallots[i] = allBallots[c.origIdx]
	}

	// 5. Build witness.
	input := &WitnessInput{
		AllBBLeaves:   allLeaves,
		ActiveIndices: activeIndices,
		IDs:           activeIDs,
		Ballots:       activeBallots,
	}
	assignment, err := BuildWitness(input)
	if err != nil {
		t.Fatalf("BuildWitness: %v", err)
	}

	// 6. Compile.
	cs, err := CompileCircuit()
	if err != nil {
		t.Fatalf("CompileCircuit: %v", err)
	}
	t.Logf("Constraint count: %d", cs.GetNbConstraints())

	// 7. Setup.
	pk, vk, err := Setup(cs)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// 8. Prove.
	proof, err := Prove(cs, pk, assignment)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	// 9. Verify.
	if err := Verify(vk, proof, assignment); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	t.Log("Full pipeline passed: compile -> setup -> prove -> verify")
}

// TestDeduplicationCircuitTampered verifies that modifying a ballot ID after
// witness construction causes proof generation to fail.
func TestDeduplicationCircuitTampered(t *testing.T) {
	const totalBallots = 1 << TreeDepth
	allIDs := make([]fr.Element, totalBallots)
	for i := range totalBallots {
		if _, err := allIDs[i].SetRandom(); err != nil {
			t.Fatalf("generating random ID %d: %v", i, err)
		}
	}

	allBallots := make([][BallotFieldElems]fr.Element, totalBallots)
	for i := range totalBallots {
		for j := range BallotFieldElems {
			if _, err := allBallots[i][j].SetRandom(); err != nil {
				t.Fatalf("generating random ballot data [%d][%d]: %v", i, j, err)
			}
		}
	}

	allLeaves := make([]fr.Element, totalBallots)
	for i := range totalBallots {
		elems := make([]fr.Element, 1+BallotFieldElems)
		elems[0] = allIDs[i]
		copy(elems[1:], allBallots[i][:])
		allLeaves[i] = poseidon2Hash(elems...)
	}

	type indexedID struct {
		origIdx int
		id      fr.Element
	}
	candidates := make([]indexedID, totalBallots)
	for i := range totalBallots {
		candidates[i] = indexedID{origIdx: i, id: allIDs[i]}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].id.Cmp(&candidates[j].id) < 0
	})
	active := candidates[:BatchSize]

	activeIndices := make([]int, BatchSize)
	activeIDs := make([]fr.Element, BatchSize)
	activeBallots := make([][BallotFieldElems]fr.Element, BatchSize)
	for i, c := range active {
		activeIndices[i] = c.origIdx
		activeIDs[i] = allIDs[c.origIdx]
		activeBallots[i] = allBallots[c.origIdx]
	}

	input := &WitnessInput{
		AllBBLeaves:   allLeaves,
		ActiveIndices: activeIndices,
		IDs:           activeIDs,
		Ballots:       activeBallots,
	}
	assignment, err := BuildWitness(input)
	if err != nil {
		t.Fatalf("BuildWitness: %v", err)
	}

	// Tamper: change one ID in the assignment.
	assignment.IDs[0] = big.NewInt(999999)

	cs, err := CompileCircuit()
	if err != nil {
		t.Fatalf("CompileCircuit: %v", err)
	}

	pk, _, err := Setup(cs)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Proving should fail because the tampered ID breaks Merkle inclusion
	// and the sorted-order constraint.
	_, err = Prove(cs, pk, assignment)
	if err == nil {
		t.Fatal("expected prove to fail with tampered ID, but it succeeded")
	}
	t.Logf("Tampered proof correctly failed: %v", err)
}

// TestDeduplicationCircuitPadding tests that the circuit works correctly
// when fewer than BatchSize ballots are active (padding with inactive slots).
func TestDeduplicationCircuitPadding(t *testing.T) {
	const totalBallots = 1 << TreeDepth
	const nActive = 5 // Only 5 of 10 slots used.

	allIDs := make([]fr.Element, totalBallots)
	for i := range totalBallots {
		if _, err := allIDs[i].SetRandom(); err != nil {
			t.Fatalf("generating random ID %d: %v", i, err)
		}
	}

	allBallots := make([][BallotFieldElems]fr.Element, totalBallots)
	for i := range totalBallots {
		for j := range BallotFieldElems {
			if _, err := allBallots[i][j].SetRandom(); err != nil {
				t.Fatalf("generating random ballot data [%d][%d]: %v", i, j, err)
			}
		}
	}

	allLeaves := make([]fr.Element, totalBallots)
	for i := range totalBallots {
		elems := make([]fr.Element, 1+BallotFieldElems)
		elems[0] = allIDs[i]
		copy(elems[1:], allBallots[i][:])
		allLeaves[i] = poseidon2Hash(elems...)
	}

	type indexedID struct {
		origIdx int
		id      fr.Element
	}
	candidates := make([]indexedID, totalBallots)
	for i := range totalBallots {
		candidates[i] = indexedID{origIdx: i, id: allIDs[i]}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].id.Cmp(&candidates[j].id) < 0
	})
	// Only take nActive entries.
	active := candidates[:nActive]

	activeIndices := make([]int, nActive)
	activeIDs := make([]fr.Element, nActive)
	activeBallots := make([][BallotFieldElems]fr.Element, nActive)
	for i, c := range active {
		activeIndices[i] = c.origIdx
		activeIDs[i] = allIDs[c.origIdx]
		activeBallots[i] = allBallots[c.origIdx]
	}

	input := &WitnessInput{
		AllBBLeaves:   allLeaves,
		ActiveIndices: activeIndices,
		IDs:           activeIDs,
		Ballots:       activeBallots,
	}
	assignment, err := BuildWitness(input)
	if err != nil {
		t.Fatalf("BuildWitness: %v", err)
	}

	cs, err := CompileCircuit()
	if err != nil {
		t.Fatalf("CompileCircuit: %v", err)
	}
	t.Logf("Constraint count (padding test): %d", cs.GetNbConstraints())

	pk, vk, err := Setup(cs)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	proof, err := Prove(cs, pk, assignment)
	if err != nil {
		t.Fatalf("Prove with padding: %v", err)
	}

	if err := Verify(vk, proof, assignment); err != nil {
		t.Fatalf("Verify with padding: %v", err)
	}

	t.Logf("Padding test passed: %d active of %d slots", nActive, BatchSize)
}
