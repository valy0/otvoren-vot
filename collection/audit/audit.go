// Package audit generates signed override reports for public verification.
//
// The report consists of two files: a signed header (ReportHeader) and a
// companion chains file containing JCS-serialized override chain DTOs.
// Chain identifiers are blinded with a per-report HMAC nonce so that the
// same voter produces different chain IDs across reports, preventing
// cross-report linkability.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/gowebpki/jcs"

	"github.com/valy0/otvoren-vot/collection/votermap"
)

// ChainProvider is the read-only data source for override chains.
// Satisfied by PostgresStore (which implements both Store and AuditStore).
type ChainProvider interface {
	GetAllOverrideChains(ctx context.Context, fn func(votermap.OverrideChain) error) error
	Size(ctx context.Context) (int, error)
}

// ReportSigner signs data and provides the public key.
type ReportSigner interface {
	Sign(data []byte) ([]byte, error)
	PublicKey() []byte
}

// Generator constructs and signs override reports.
type Generator struct {
	chains     ChainProvider
	signer     ReportSigner
	electionID string
	historyKey []byte // for row_hash chain verification
}

// NewGenerator creates a report generator.
func NewGenerator(chains ChainProvider, signer ReportSigner, electionID string, historyKey []byte) *Generator {
	return &Generator{
		chains:     chains,
		signer:     signer,
		electionID: electionID,
		historyKey: historyKey,
	}
}

// Generate produces a signed override report and writes two outputs:
//   - headerOut receives the JCS-serialized, signed ReportHeader
//   - chainsOut receives the JCS-serialized array of ChainDTOs
//
// bbMerkleRoot is the current bulletin board Merkle root (hex-encoded),
// included in the header for cross-layer binding.
func (g *Generator) Generate(ctx context.Context, bbMerkleRoot string, headerOut, chainsOut io.Writer) error {
	// 1. Generate 256-bit report nonce from crypto/rand.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	// 2-3. Stream chains, verify hash chain integrity, build DTOs.
	var chainDTOs []ChainDTO
	err := g.chains.GetAllOverrideChains(ctx, func(chain votermap.OverrideChain) error {
		if err := verifyHashChain(g.historyKey, chain); err != nil {
			return fmt.Errorf("corrupt hash chain for voter: %w", err)
		}

		// Compute blinded chain_id: HMAC-SHA256(nonce, egn_hash).
		chainID := hmacSHA256(nonce, []byte(chain.EgnHash))

		subs := make([]SubmissionDTO, len(chain.Submissions))
		for i, s := range chain.Submissions {
			subs[i] = SubmissionDTO{
				BallotID:    s.BallotID,
				Seq:         s.Seq,
				Channel:     string(s.Channel),
				SubmittedAt: s.SubmittedAt.UTC().Format(time.RFC3339),
			}
		}
		chainDTOs = append(chainDTOs, ChainDTO{
			ChainID:        hex.EncodeToString(chainID),
			Submissions:    subs,
			ActiveBallotID: chain.ActiveBallotID(),
		})
		return nil
	})
	if err != nil {
		return fmt.Errorf("read override chains: %w", err)
	}

	// 4. Sort chains by chain_id for deterministic output.
	sort.Slice(chainDTOs, func(i, j int) bool {
		return chainDTOs[i].ChainID < chainDTOs[j].ChainID
	})

	// 5. Serialize each chain as JCS, build Merkle leaves.
	leaves := make([][]byte, len(chainDTOs))
	for i, dto := range chainDTOs {
		raw, err := json.Marshal(dto)
		if err != nil {
			return fmt.Errorf("marshal chain %s: %w", dto.ChainID, err)
		}
		canonical, err := jcs.Transform(raw)
		if err != nil {
			return fmt.Errorf("canonicalize chain %s: %w", dto.ChainID, err)
		}
		leaves[i] = canonical
	}

	// 6. Build Merkle tree over JCS-serialized chains.
	root := chainsMerkleRoot(leaves)

	// 7. Get total voter count (including non-overriders).
	totalVoters, err := g.chains.Size(ctx)
	if err != nil {
		return fmt.Errorf("get total voters: %w", err)
	}

	// 8. Write chains file, compute SHA-256 of the canonical output.
	chainsJSON, err := json.Marshal(chainDTOs)
	if err != nil {
		return fmt.Errorf("marshal chains: %w", err)
	}
	chainsCanonical, err := jcs.Transform(chainsJSON)
	if err != nil {
		return fmt.Errorf("canonicalize chains: %w", err)
	}
	chainsHash := sha256.Sum256(chainsCanonical)
	if _, err := chainsOut.Write(chainsCanonical); err != nil {
		return fmt.Errorf("write chains: %w", err)
	}

	// 9. Build header (signature placeholder is empty).
	header := ReportHeader{
		ElectionID:               g.electionID,
		GeneratedAt:              time.Now().UTC().Format(time.RFC3339),
		TotalVoters:              totalVoters,
		TotalOverrides:           len(chainDTOs),
		OverrideChainsMerkleRoot: hex.EncodeToString(root),
		ChainsFileSHA256:         hex.EncodeToString(chainsHash[:]),
		BulletinBoardMerkleRoot:  bbMerkleRoot,
		ReportNonce:              hex.EncodeToString(nonce),
		SigningPublicKey:         hex.EncodeToString(g.signer.PublicKey()),
		Signature:                "",
	}

	// 10. Sign the JCS-serialized header (with empty signature field).
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("marshal header: %w", err)
	}
	headerCanonical, err := jcs.Transform(headerJSON)
	if err != nil {
		return fmt.Errorf("canonicalize header: %w", err)
	}
	sig, err := g.signer.Sign(headerCanonical)
	if err != nil {
		return fmt.Errorf("sign header: %w", err)
	}
	header.Signature = hex.EncodeToString(sig)

	// Write the final header with the real signature.
	finalHeaderJSON, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("marshal final header: %w", err)
	}
	finalCanonical, err := jcs.Transform(finalHeaderJSON)
	if err != nil {
		return fmt.Errorf("canonicalize final header: %w", err)
	}
	if _, err := headerOut.Write(finalCanonical); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	return nil
}

// verifyHashChain checks that each row's hash chains correctly from the previous.
func verifyHashChain(key []byte, chain votermap.OverrideChain) error {
	prevHash := ""
	for _, entry := range chain.Submissions {
		expected := votermap.ComputeRowHash(key, prevHash, chain.EgnHash, entry.BallotID, entry.Seq)
		if entry.RowHash != expected {
			return fmt.Errorf("seq %d: expected hash %s, got %s", entry.Seq, expected, entry.RowHash)
		}
		prevHash = entry.RowHash
	}
	return nil
}

// hmacSHA256 computes HMAC-SHA256(key, data).
func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
