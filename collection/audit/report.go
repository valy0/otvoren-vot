package audit

// ReportHeader is the signed metadata for the override report.
// All fields are serialized with JCS (RFC 8785) before signing.
type ReportHeader struct {
	ElectionID               string `json:"election_id"`
	GeneratedAt              string `json:"generated_at"`
	TotalVoters              int    `json:"total_voters"`
	TotalOverrides           int    `json:"total_overrides"`
	OverrideChainsMerkleRoot string `json:"override_chains_merkle_root"`
	ChainsFileSHA256         string `json:"chains_file_sha256"`
	BulletinBoardMerkleRoot  string `json:"bulletin_board_merkle_root"`
	ReportNonce              string `json:"report_nonce"`
	SigningPublicKey         string `json:"signing_public_key"`
	Signature                string `json:"signature"`
}

// ChainDTO is the JSON representation of one override chain.
// ChainID is a blinded (HMAC) identifier derived from a per-report nonce,
// so the same voter produces different chain IDs across reports.
type ChainDTO struct {
	ChainID        string          `json:"chain_id"`
	Submissions    []SubmissionDTO `json:"submissions"`
	ActiveBallotID string          `json:"active_ballot_id"`
}

// SubmissionDTO is the JSON representation of one ballot submission
// within an override chain.
type SubmissionDTO struct {
	BallotID    string `json:"ballot_id"`
	Seq         int    `json:"seq"`
	Channel     string `json:"channel"`
	SubmittedAt string `json:"submitted_at"`
}
