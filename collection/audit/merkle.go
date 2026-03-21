package audit

import (
	"github.com/valy0/otvoren-vot/crypto/merkle"
)

// chainsMerkleRoot computes the Merkle root over JCS-serialized chain DTOs.
// Chains must already be sorted by ChainID before calling.
// Returns nil if jcsChains is empty.
func chainsMerkleRoot(jcsChains [][]byte) []byte {
	tree := merkle.New()
	for _, leaf := range jcsChains {
		tree.Append(leaf)
	}
	return tree.Root()
}
