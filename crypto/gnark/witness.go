package gnark

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	gnarkPoseidon "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

// MerkleProofData holds a single level of an out-of-circuit Merkle proof:
// the sibling hash and the direction bit (0 = node is left child, 1 = right).
type MerkleProofData struct {
	Sibling   fr.Element
	Direction int // 0 or 1
}

// WitnessInput contains the plaintext data needed to build a full circuit
// witness for the DeduplicationCircuit.
type WitnessInput struct {
	// AllBBLeaves is the complete set of ballot leaves in the bulletin-board
	// Merkle tree. Each leaf = Poseidon2(ID, ballot[0..BallotFieldElems-1]).
	// The tree is padded to the next power of 2 internally.
	AllBBLeaves []fr.Element

	// ActiveIndices maps each batch slot [0, BatchSize) to the index of the
	// corresponding leaf in AllBBLeaves. Slots beyond len(ActiveIndices) are
	// padding.
	ActiveIndices []int

	// IDs contains the ballot ID for each active entry. Must be sorted in
	// strictly ascending order. len(IDs) == len(ActiveIndices).
	IDs []fr.Element

	// Ballots contains the ballot field elements for each active entry.
	// len(Ballots) == len(ActiveIndices), each inner slice has BallotFieldElems.
	Ballots [][BallotFieldElems]fr.Element
}

// BuildWitness constructs a fully populated DeduplicationCircuit assignment
// from the given input. It computes all Merkle roots and proofs out-of-circuit
// using the native Poseidon2 hasher, which must produce identical results to
// the in-circuit hasher.
func BuildWitness(input *WitnessInput) (*DeduplicationCircuit, error) {
	nActive := len(input.ActiveIndices)
	if nActive > BatchSize {
		return nil, fmt.Errorf("active count %d exceeds BatchSize %d", nActive, BatchSize)
	}
	if len(input.IDs) != nActive {
		return nil, errors.New("IDs length must equal ActiveIndices length")
	}
	if len(input.Ballots) != nActive {
		return nil, errors.New("Ballots length must equal ActiveIndices length")
	}

	// Verify IDs are strictly ascending.
	for i := 1; i < nActive; i++ {
		if input.IDs[i].Cmp(&input.IDs[i-1]) <= 0 {
			return nil, fmt.Errorf("IDs not strictly ascending at index %d", i)
		}
	}

	var circuit DeduplicationCircuit

	// ---------------------------------------------------------------
	// Compute ballot leaf hashes: leaf = Poseidon2(ID, ballot[0..9])
	// ---------------------------------------------------------------
	ballotLeaves := make([]fr.Element, nActive)
	for i := 0; i < nActive; i++ {
		elems := make([]fr.Element, 1+BallotFieldElems)
		elems[0] = input.IDs[i]
		copy(elems[1:], input.Ballots[i][:])
		ballotLeaves[i] = poseidon2Hash(elems...)
	}

	// ---------------------------------------------------------------
	// Build the BB Merkle tree and extract inclusion proofs.
	// ---------------------------------------------------------------
	bbRoot, bbProofs, err := buildPoseidon2MerkleTree(input.AllBBLeaves)
	if err != nil {
		return nil, fmt.Errorf("building BB Merkle tree: %w", err)
	}

	circuit.BBRoot = bbRoot
	circuit.NActive = nActive

	// ---------------------------------------------------------------
	// Fill per-slot data.
	// ---------------------------------------------------------------
	for i := range BatchSize {
		if i < nActive {
			// Active slot.
			circuit.IsActive[i] = 1
			circuit.IDs[i] = input.IDs[i]

			for j := range BallotFieldElems {
				circuit.Ballots[i][j] = input.Ballots[i][j]
			}

			// BB Merkle proof.
			bbIdx := input.ActiveIndices[i]
			proof, ok := bbProofs[bbIdx]
			if !ok {
				return nil, fmt.Errorf("no BB Merkle proof for leaf index %d", bbIdx)
			}
			if len(proof) != TreeDepth {
				return nil, fmt.Errorf("BB Merkle proof for index %d has depth %d, want %d", bbIdx, len(proof), TreeDepth)
			}
			for d := range TreeDepth {
				circuit.MerkleProofs[i].Path[d] = proof[d].Sibling
				circuit.MerkleProofs[i].Direction[d] = proof[d].Direction
			}
		} else {
			// Padding slot: all zeros.
			circuit.IsActive[i] = 0
			circuit.IDs[i] = 0

			for j := range BallotFieldElems {
				circuit.Ballots[i][j] = 0
			}
			for d := range TreeDepth {
				circuit.MerkleProofs[i].Path[d] = 0
				circuit.MerkleProofs[i].Direction[d] = 0
			}
		}
	}

	// ---------------------------------------------------------------
	// (c) Active-set commitment: Poseidon2 Merkle root of IDs.
	// ---------------------------------------------------------------
	asLeaves := make([]fr.Element, BatchSize)
	for i := range BatchSize {
		if i < nActive {
			asLeaves[i] = input.IDs[i]
		}
		// else: zero-valued fr.Element (padding)
	}
	asRoot, _, err := buildPoseidon2MerkleTree(asLeaves)
	if err != nil {
		return nil, fmt.Errorf("building AS Merkle tree: %w", err)
	}
	circuit.ASCommitment = asRoot

	// ---------------------------------------------------------------
	// (d) Final-set root: Poseidon2 Merkle root of ballot leaf hashes.
	//     Inactive slots use 0 as leaf.
	// ---------------------------------------------------------------
	fsLeaves := make([]fr.Element, BatchSize)
	for i := range BatchSize {
		if i < nActive {
			fsLeaves[i] = ballotLeaves[i]
		}
		// else: zero-valued fr.Element (padding)
	}
	fsRoot, _, err := buildPoseidon2MerkleTree(fsLeaves)
	if err != nil {
		return nil, fmt.Errorf("building FS Merkle tree: %w", err)
	}
	circuit.FSRoot = fsRoot

	return &circuit, nil
}

// poseidon2Hash hashes one or more field elements using the out-of-circuit
// Poseidon2 Merkle-Damgard hasher and returns the digest as a field element.
func poseidon2Hash(inputs ...fr.Element) fr.Element {
	h := gnarkPoseidon.NewMerkleDamgardHasher()
	for _, elem := range inputs {
		b := elem.Marshal()
		_, _ = h.Write(b) // hash.Hash Write never errors
	}
	digest := h.Sum(nil)

	var result fr.Element
	result.SetBytes(digest)
	return result
}

// buildPoseidon2MerkleTree builds a Poseidon2 Merkle tree from the given
// leaves (padded to the next power of 2 with zeros) and returns the root
// plus inclusion proofs for every original leaf.
func buildPoseidon2MerkleTree(leaves []fr.Element) (fr.Element, map[int][]MerkleProofData, error) {
	if len(leaves) == 0 {
		return fr.Element{}, nil, errors.New("empty leaves")
	}

	n := nextPowerOf2(len(leaves))
	layer := make([]fr.Element, n)
	copy(layer, leaves)
	// Remaining slots are zero-valued fr.Element (padding).

	// Store all layers for proof extraction.
	layers := [][]fr.Element{layer}

	for len(layer) > 1 {
		next := make([]fr.Element, len(layer)/2)
		for i := 0; i < len(layer); i += 2 {
			next[i/2] = poseidon2Hash(layer[i], layer[i+1])
		}
		layers = append(layers, next)
		layer = next
	}

	root := layers[len(layers)-1][0]

	// Extract inclusion proofs.
	proofs := make(map[int][]MerkleProofData, len(leaves))
	for leafIdx := range leaves {
		proof := make([]MerkleProofData, 0, len(layers)-1)
		idx := leafIdx
		for level := 0; level < len(layers)-1; level++ {
			siblingIdx := idx ^ 1
			direction := idx & 1 // 0 if left child, 1 if right child
			proof = append(proof, MerkleProofData{
				Sibling:   layers[level][siblingIdx],
				Direction: direction,
			})
			idx >>= 1
		}
		proofs[leafIdx] = proof
	}

	return root, proofs, nil
}

// FrFromBigInt converts a *big.Int to an fr.Element.
func FrFromBigInt(v *big.Int) fr.Element {
	var e fr.Element
	e.SetBigInt(v)
	return e
}
