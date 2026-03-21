package board

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/valy0/otvoren-vot/bulletin-board/store"
	"github.com/valy0/otvoren-vot/crypto/merkle"
)

var (
	ErrBoardSealed    = errors.New("board is sealed")
	ErrDuplicateBallot = errors.New("ballot ID already exists")
)

// Board manages the bulletin board state.
type Board struct {
	store      *store.Store
	tree       *merkle.Tree
	mu         sync.Mutex
	sealed     bool
	validateFn func(encryptedBallot, zkProofs json.RawMessage) error // nil = skip validation
}

// SetValidator sets the proof validation function.
// When set, AppendBallot will reject ballots that fail validation.
func (b *Board) SetValidator(fn func(encryptedBallot, zkProofs json.RawMessage) error) {
	b.validateFn = fn
}

// New creates a Board. It rebuilds the Merkle tree from existing data.
func New(ctx context.Context, s *store.Store) (*Board, error) {
	b := &Board{store: s, tree: merkle.New()}

	// Rebuild tree from existing ballots
	leaves, err := s.GetAllLeafData(ctx)
	if err != nil {
		return nil, err
	}
	for _, leaf := range leaves {
		b.tree.Append(leaf)
	}

	return b, nil
}

// AppendResult is returned after a successful ballot append.
type AppendResult struct {
	Position   int64
	MerkleRoot string
}

// AppendBallot validates proofs and appends a ballot to the board.
func (b *Board) AppendBallot(ctx context.Context, ballotID string, encryptedBallot, zkProofs json.RawMessage) (*AppendResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.sealed {
		return nil, ErrBoardSealed
	}

	// Check duplicate
	existing, err := b.store.GetBallot(ctx, ballotID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrDuplicateBallot
	}

	// Validate ZK proofs if validator is set
	if b.validateFn != nil {
		if err := b.validateFn(encryptedBallot, zkProofs); err != nil {
			return nil, fmt.Errorf("proof validation failed: %w", err)
		}
	}

	// Get next position
	maxPos, err := b.store.GetMaxPosition(ctx)
	if err != nil {
		return nil, err
	}
	position := maxPos + 1

	// Canonical leaf encoding with length prefixes
	leafData := EncodeLeaf(ballotID, encryptedBallot, zkProofs)
	b.tree.Append(leafData)

	root := hex.EncodeToString(b.tree.Root())

	// Store in database
	rec := &store.BallotRecord{
		BallotID:        ballotID,
		EncryptedBallot: encryptedBallot,
		ZKProofs:        zkProofs,
		Position:        position,
		MerkleRootSHA:   root,
	}
	if err := b.store.InsertBallot(ctx, rec); err != nil {
		return nil, err
	}

	return &AppendResult{Position: position, MerkleRoot: root}, nil
}

// GetBallot retrieves a ballot and its Merkle inclusion proof.
func (b *Board) GetBallot(ctx context.Context, ballotID string) (*store.BallotRecord, []merkle.ProofNode, error) {
	rec, err := b.store.GetBallot(ctx, ballotID)
	if err != nil {
		return nil, nil, err
	}
	if rec == nil {
		return nil, nil, nil
	}

	proof, err := b.tree.InclusionProof(int(rec.Position - 1)) // 0-based index
	if err != nil {
		return nil, nil, err
	}

	return rec, proof, nil
}

// Root returns the current Merkle root as hex string.
func (b *Board) Root() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.tree.Root()
	if r == nil {
		return ""
	}
	return hex.EncodeToString(r)
}

// Size returns the number of ballots.
func (b *Board) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tree.Size()
}

// Seal marks the board as read-only. No more ballots can be appended.
func (b *Board) Seal() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sealed = true
}

// IsSealed returns whether the board is sealed.
func (b *Board) IsSealed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sealed
}

// InclusionProof returns the Merkle proof for a given position (1-based).
func (b *Board) InclusionProof(position int64) ([]merkle.ProofNode, error) {
	return b.tree.InclusionProof(int(position - 1))
}

// MerkleTree returns the underlying tree for consistency proofs.
func (b *Board) MerkleTree() *merkle.Tree {
	return b.tree
}

// Store returns the underlying store for read operations.
func (b *Board) Store() *store.Store { return b.store }

// EncodeLeaf produces canonical leaf encoding with length prefixes.
// This must match the encoding used in store.GetAllLeafData for tree rebuilds.
func EncodeLeaf(ballotID string, encryptedBallot, zkProofs json.RawMessage) []byte {
	var buf bytes.Buffer
	idBytes := []byte(ballotID)
	binary.Write(&buf, binary.BigEndian, uint32(len(idBytes)))
	buf.Write(idBytes)
	binary.Write(&buf, binary.BigEndian, uint32(len(encryptedBallot)))
	buf.Write(encryptedBallot)
	binary.Write(&buf, binary.BigEndian, uint32(len(zkProofs)))
	buf.Write(zkProofs)
	return buf.Bytes()
}
