package merkle

import (
	"crypto/sha256"
	"errors"
)

// Tree is an append-only SHA-256 Merkle tree with O(log n) incremental updates.
//
// Internally it maintains the hash at every tree level so that each Append
// recomputes only the O(log n) nodes on the rightmost path, and Root returns
// the cached root in O(1).
type Tree struct {
	leaves [][]byte   // raw leaf data (kept for inclusion proofs)
	levels [][][]byte // levels[0] = leaf hashes, levels[H] = [root]
}

// New creates an empty Merkle tree.
func New() *Tree {
	return &Tree{}
}

// Append adds a leaf to the tree and incrementally updates the internal
// hash levels. This is O(log n) in the number of existing leaves.
func (t *Tree) Append(data []byte) {
	cp := make([]byte, len(data))
	copy(cp, data)
	t.leaves = append(t.leaves, cp)

	h := hashLeaf(data)

	// Ensure level 0 exists.
	if len(t.levels) == 0 {
		t.levels = append(t.levels, nil)
	}
	t.levels[0] = append(t.levels[0], h)

	// Propagate up the tree. At each level the affected node is always the
	// last element, so we can locate it via len(levels[L])-1.
	for L := 0; ; L++ {
		n := len(t.levels[L])
		if n <= 1 {
			// Single element at this level — it is the current root.
			break
		}

		lastIdx := n - 1
		parentIdx := lastIdx / 2

		// Compute the parent hash. When the last element is unpaired
		// (even index, i.e. the level has an odd count) we duplicate it,
		// matching the behaviour of the original computeRoot.
		var parent []byte
		if lastIdx%2 == 0 {
			parent = hashPair(t.levels[L][lastIdx], t.levels[L][lastIdx])
		} else {
			parent = hashPair(t.levels[L][lastIdx-1], t.levels[L][lastIdx])
		}

		// Ensure the next level exists.
		if L+1 >= len(t.levels) {
			t.levels = append(t.levels, nil)
		}

		if parentIdx >= len(t.levels[L+1]) {
			t.levels[L+1] = append(t.levels[L+1], parent)
		} else {
			t.levels[L+1][parentIdx] = parent
		}
	}
}

// Root returns the current Merkle root, or nil if the tree is empty. O(1).
func (t *Tree) Root() []byte {
	if len(t.leaves) == 0 {
		return nil
	}
	top := t.levels[len(t.levels)-1]
	return top[0]
}

// Size returns the number of leaves.
func (t *Tree) Size() int {
	return len(t.leaves)
}

// ProofNode is a sibling hash in an inclusion proof.
type ProofNode struct {
	Hash   []byte
	IsLeft bool
}

// InclusionProof returns the Merkle proof for the leaf at index.
func (t *Tree) InclusionProof(index int) ([]ProofNode, error) {
	if index < 0 || index >= len(t.leaves) {
		return nil, errors.New("index out of range")
	}
	if len(t.leaves) == 1 {
		return nil, nil
	}

	hashes := make([][]byte, len(t.leaves))
	for i, leaf := range t.leaves {
		hashes[i] = hashLeaf(leaf)
	}

	var proof []ProofNode
	idx := index
	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		sibling := idx ^ 1
		proof = append(proof, ProofNode{
			Hash:   hashes[sibling],
			IsLeft: sibling < idx,
		})
		next := make([][]byte, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			next[i/2] = hashPair(hashes[i], hashes[i+1])
		}
		hashes = next
		idx /= 2
	}
	return proof, nil
}

// VerifyInclusion verifies a Merkle inclusion proof.
func VerifyInclusion(root, data []byte, index, size int, proof []ProofNode) bool {
	if size == 0 {
		return false
	}
	h := hashLeaf(data)
	for _, p := range proof {
		if p.IsLeft {
			h = hashPair(p.Hash, h)
		} else {
			h = hashPair(h, p.Hash)
		}
	}
	return bytesEqual(h, root)
}

// computeRoot computes the Merkle root from a flat slice of hashes using the
// duplicate-last-element strategy for odd-length levels. Retained for testing
// and for InclusionProof's internal computation.
func computeRoot(hashes [][]byte) []byte {
	if len(hashes) == 1 {
		return hashes[0]
	}
	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		next := make([][]byte, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			next[i/2] = hashPair(hashes[i], hashes[i+1])
		}
		hashes = next
	}
	return hashes[0]
}

// Domain-separated hashing: 0x00 prefix for leaves, 0x01 for internal nodes.
func hashLeaf(data []byte) []byte {
	h := sha256.Sum256(append([]byte{0x00}, data...))
	return h[:]
}

func hashPair(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
