package ceremony

// DedupProof represents a ZK deduplication proof.
// The actual gnark Groth16 circuit implementation is deferred to a later phase.
// This stub defines the interface that the tally service will use.
type DedupProof struct {
	// Groth16 proof bytes (to be implemented with gnark)
	ProofBytes []byte `json:"proof_bytes"`
	// Public inputs
	BoardMerkleRoot     string `json:"board_merkle_root"`
	ActiveSetCommitment string `json:"active_set_commitment"`
	FilteredSetRoot     string `json:"filtered_set_root"`
	ActiveSetSize       int    `json:"active_set_size"`
}

// GenerateDedupProof generates the ZK deduplication proof.
// TODO: Implement gnark Groth16 circuit with Poseidon Merkle proofs.
// For now, returns a placeholder proof.
func GenerateDedupProof(activeSetIDs []string, boardRoot string) (*DedupProof, error) {
	return &DedupProof{
		ProofBytes:          []byte("placeholder-proof"),
		BoardMerkleRoot:     boardRoot,
		ActiveSetCommitment: "placeholder-commitment",
		FilteredSetRoot:     "placeholder-filtered-root",
		ActiveSetSize:       len(activeSetIDs),
	}, nil
}
