package gnark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

// Circuit sizing constants. BatchSize is the number of ballot slots (active +
// padding) per batch. TreeDepth is the depth of the bulletin-board Merkle tree
// that each active ballot proves inclusion in. BallotFieldElems is the number
// of field elements per encrypted ballot.
const (
	BatchSize        = 10
	TreeDepth        = 5
	BallotFieldElems = 10
)

// DeduplicationCircuit is a Groth16 circuit that proves a batch of ballots
// was correctly deduplicated. It enforces:
//
//   - (0) NActive matches the number of active entries.
//   - (a) Every active ballot has a valid Merkle inclusion proof against BBRoot.
//   - (b) Active ballot IDs are in strictly ascending order (no duplicates).
//   - (c) ASCommitment is the Poseidon2 Merkle root of the active-set IDs.
//   - (d) FSRoot is the Poseidon2 Merkle root of the active ballot leaves.
//
// Inactive (padded) slots have IsActive[i] == 0 and are skipped.
type DeduplicationCircuit struct {
	// --- Public inputs ---

	// BBRoot is the bulletin-board Poseidon2 Merkle root that all active
	// ballots must prove inclusion in.
	BBRoot frontend.Variable `gnark:",public"`

	// ASCommitment is the expected Poseidon2 Merkle root of the active-set
	// ballot IDs (constraint group c).
	ASCommitment frontend.Variable `gnark:",public"`

	// FSRoot is the expected Poseidon2 Merkle root of the final ballot
	// leaves: each leaf is Poseidon2(ballot field elements) (constraint group d).
	FSRoot frontend.Variable `gnark:",public"`

	// NActive is the number of active (non-padded) entries in this batch.
	NActive frontend.Variable `gnark:",public"`

	// --- Private witness ---

	// IDs are the ballot identifiers. Active entries are sorted ascending;
	// padded entries can be zero.
	IDs [BatchSize]frontend.Variable

	// MerkleProofs are the Merkle inclusion proofs for each ballot in the
	// bulletin-board tree.
	MerkleProofs [BatchSize]CircuitMerkleProof

	// Ballots contains the encrypted ballot data, each consisting of
	// BallotFieldElems field elements.
	Ballots [BatchSize][BallotFieldElems]frontend.Variable

	// IsActive is 1 for real ballots and 0 for padding slots.
	IsActive [BatchSize]frontend.Variable
}

// CircuitMerkleProof is a fixed-depth Merkle proof for use inside the circuit.
type CircuitMerkleProof struct {
	Path      [TreeDepth]frontend.Variable
	Direction [TreeDepth]frontend.Variable
}

// Define implements frontend.Circuit. It lays out all constraint groups.
func (c *DeduplicationCircuit) Define(api frontend.API) error {
	h, err := newPoseidon2Hasher(api)
	if err != nil {
		return err
	}
	rc := rangecheck.New(api)

	// Constrain IsActive to be boolean (0 or 1).
	for i := range BatchSize {
		api.AssertIsBoolean(c.IsActive[i])
	}

	// ---------------------------------------------------------------
	// (0) Count active entries and assert count == NActive.
	// ---------------------------------------------------------------
	activeCount := frontend.Variable(0)
	for i := range BatchSize {
		activeCount = api.Add(activeCount, c.IsActive[i])
	}
	api.AssertIsEqual(activeCount, c.NActive)

	// ---------------------------------------------------------------
	// (a) Merkle inclusion: each active ballot's leaf must be included
	//     in the bulletin-board tree rooted at BBRoot.
	//     leaf = Poseidon2(ID, ballot[0], ..., ballot[BallotFieldElems-1])
	// ---------------------------------------------------------------
	ballotLeaves := make([]frontend.Variable, BatchSize)
	for i := range BatchSize {
		// Compute the ballot leaf hash.
		h.Reset()
		h.Write(c.IDs[i])
		for j := range BallotFieldElems {
			h.Write(c.Ballots[i][j])
		}
		ballotLeaves[i] = h.Sum()

		// Walk the Merkle proof to compute the root.
		computedRoot := ballotLeaves[i]
		for d := range TreeDepth {
			left := api.Select(c.MerkleProofs[i].Direction[d], c.MerkleProofs[i].Path[d], computedRoot)
			right := api.Select(c.MerkleProofs[i].Direction[d], computedRoot, c.MerkleProofs[i].Path[d])
			h.Reset()
			h.Write(left, right)
			computedRoot = h.Sum()
		}

		// For active: assert computedRoot == BBRoot.
		// For inactive: skip (select BBRoot so equality trivially holds).
		conditionalRoot := api.Select(c.IsActive[i], computedRoot, c.BBRoot)
		api.AssertIsEqual(conditionalRoot, c.BBRoot)
	}

	// ---------------------------------------------------------------
	// (b) Sorted order: active IDs must be strictly ascending.
	//     For each consecutive pair of active entries, enforce that
	//     IDs[i+1] - IDs[i] > 0 by range-checking the difference.
	//     For inactive slots, the constraint is skipped.
	// ---------------------------------------------------------------
	for i := 0; i < BatchSize-1; i++ {
		diff := api.Sub(c.IDs[i+1], c.IDs[i])

		// bothActive = IsActive[i] AND IsActive[i+1]
		bothActive := api.Mul(c.IsActive[i], c.IsActive[i+1])

		// When both are active, diff must be in [1, 2^252 - 1].
		// We check diff - 1 fits in 252 bits, which proves diff >= 1
		// and diff <= 2^252 (which is well within the BN254 field).
		diffMinusOne := api.Sub(diff, 1)

		// Conditional: if not both active, substitute 0 (which trivially passes).
		checkedValue := api.Select(bothActive, diffMinusOne, frontend.Variable(0))
		rc.Check(checkedValue, 252)
	}

	// ---------------------------------------------------------------
	// (c) Active-set commitment: ASCommitment must equal the Poseidon2
	//     Merkle root of the active IDs.
	//     For inactive slots, use ID 0 as padding in the Merkle tree.
	// ---------------------------------------------------------------
	asLeaves := make([]frontend.Variable, BatchSize)
	for i := range BatchSize {
		asLeaves[i] = api.Select(c.IsActive[i], c.IDs[i], frontend.Variable(0))
	}

	asRoot, err := BuildMerkleTree(api, asLeaves)
	if err != nil {
		return err
	}
	api.AssertIsEqual(asRoot, c.ASCommitment)

	// ---------------------------------------------------------------
	// (d) Final-set root: FSRoot must equal the Poseidon2 Merkle root
	//     of the ballot leaf hashes.
	//     For inactive slots, use 0 as the leaf.
	// ---------------------------------------------------------------
	fsLeaves := make([]frontend.Variable, BatchSize)
	for i := range BatchSize {
		fsLeaves[i] = api.Select(c.IsActive[i], ballotLeaves[i], frontend.Variable(0))
	}

	fsRoot, err := BuildMerkleTree(api, fsLeaves)
	if err != nil {
		return err
	}
	api.AssertIsEqual(fsRoot, c.FSRoot)

	return nil
}
