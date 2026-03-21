package merkle

import (
	"crypto/sha256"
	"errors"
)

// Tree is an append-only SHA-256 Merkle tree.
type Tree struct {
	leaves [][]byte
}

// New creates an empty Merkle tree.
func New() *Tree {
	return &Tree{}
}

// Append adds a leaf to the tree.
func (t *Tree) Append(data []byte) {
	t.leaves = append(t.leaves, data)
}

// Root returns the current Merkle root, or nil if empty.
func (t *Tree) Root() []byte {
	if len(t.leaves) == 0 {
		return nil
	}
	hashes := make([][]byte, len(t.leaves))
	for i, leaf := range t.leaves {
		hashes[i] = hashLeaf(leaf)
	}
	return computeRoot(hashes)
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
