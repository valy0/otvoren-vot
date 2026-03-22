// Package gnark implements a Groth16 deduplication circuit for ballot
// deduplication in the otvoren-vot voting system. It uses Poseidon2 hashing
// over BN254 for SNARK-friendly Merkle trees and commitment schemes.
package gnark

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

// BN254 Poseidon2 default parameters (width=2, fullRounds=6, partialRounds=50).
// These must match gnark-crypto's GetDefaultParameters for bn254/fr/poseidon2.
const (
	poseidon2Width         = 2
	poseidon2FullRounds    = 6
	poseidon2PartialRounds = 50
)

// newPoseidon2Hasher creates a Poseidon2 Merkle-Damgard hasher for BN254.
// The default NewMerkleDamgardHasher in gnark's std/hash/poseidon2 only
// supports BLS12-377. We construct one explicitly using NewPoseidon2FromParameters
// which does support BN254.
func newPoseidon2Hasher(api frontend.API) (hash.FieldHasher, error) {
	perm, err := poseidon2.NewPoseidon2FromParameters(api, poseidon2Width, poseidon2FullRounds, poseidon2PartialRounds)
	if err != nil {
		return nil, fmt.Errorf("creating poseidon2 permutation for BN254: %w", err)
	}
	return hash.NewMerkleDamgardHasher(api, perm, 0), nil
}

// BuildMerkleTree computes a Poseidon2 Merkle root from the given leaves
// inside a gnark circuit. Leaves are padded to the next power of 2 using
// zeros before building the tree bottom-up.
func BuildMerkleTree(api frontend.API, leaves []frontend.Variable) (frontend.Variable, error) {
	if len(leaves) == 0 {
		return 0, nil
	}

	n := nextPowerOf2(len(leaves))
	layer := make([]frontend.Variable, n)
	copy(layer, leaves)
	for i := len(leaves); i < n; i++ {
		layer[i] = frontend.Variable(0)
	}

	h, err := newPoseidon2Hasher(api)
	if err != nil {
		return nil, err
	}

	for len(layer) > 1 {
		next := make([]frontend.Variable, len(layer)/2)
		for i := 0; i < len(layer); i += 2 {
			h.Reset()
			h.Write(layer[i], layer[i+1])
			next[i/2] = h.Sum()
		}
		layer = next
	}

	return layer[0], nil
}

// MerkleProof represents a fixed-depth Merkle inclusion proof for use
// inside a gnark circuit. Each level has a sibling hash and a direction
// bit (0 = current node is left child, 1 = current node is right child).
type MerkleProof struct {
	// Path contains the sibling hashes at each level, from leaf to root.
	Path []frontend.Variable
	// Direction contains the side bits: 0 means the node is the left child,
	// 1 means it is the right child.
	Direction []frontend.Variable
}

// VerifyMerkleProof checks a Poseidon2 Merkle inclusion proof inside a
// gnark circuit. It walks from the leaf up to the root using api.Select
// to handle left/right ordering at each level, then asserts the computed
// root equals the expected root.
func VerifyMerkleProof(api frontend.API, leaf, expectedRoot frontend.Variable, proof MerkleProof) error {
	h, err := newPoseidon2Hasher(api)
	if err != nil {
		return err
	}

	current := leaf
	for i := range proof.Path {
		// If Direction[i] == 0, current is left child: hash(current, sibling)
		// If Direction[i] == 1, current is right child: hash(sibling, current)
		left := api.Select(proof.Direction[i], proof.Path[i], current)
		right := api.Select(proof.Direction[i], current, proof.Path[i])

		h.Reset()
		h.Write(left, right)
		current = h.Sum()
	}

	api.AssertIsEqual(current, expectedRoot)
	return nil
}

// nextPowerOf2 returns the smallest power of 2 >= n.
func nextPowerOf2(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}
