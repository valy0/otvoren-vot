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
	ErrBoardSealed      = errors.New("board is sealed")
	ErrDuplicateBallot  = errors.New("ballot ID already exists")
	ErrPositionConflict = errors.New("position conflict")
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

// New creates a Board. It rebuilds the Merkle tree from existing data
// and restores persisted state (e.g., sealed flag) from the database.
func New(ctx context.Context, s *store.Store) (*Board, error) {
	b := &Board{store: s, tree: merkle.New()}

	// Restore sealed state from database
	sealedVal, err := s.GetBoardState(ctx, "sealed")
	if err != nil {
		return nil, fmt.Errorf("load sealed state: %w", err)
	}
	b.sealed = sealedVal == "true"

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
// The DB write happens first (with PK/unique constraints as the authoritative
// duplicate and position guards), and the in-memory Merkle tree is updated
// only after the DB confirms success.
func (b *Board) AppendBallot(ctx context.Context, ballotID string, encryptedBallot, zkProofs json.RawMessage) (*AppendResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.sealed {
		return nil, ErrBoardSealed
	}

	// Validate ZK proofs if validator is set
	if b.validateFn != nil {
		if err := b.validateFn(encryptedBallot, zkProofs); err != nil {
			return nil, fmt.Errorf("proof validation failed: %w", err)
		}
	}

	// Canonical leaf encoding with length prefixes
	leafData := EncodeLeaf(ballotID, encryptedBallot, zkProofs)

	// DB-first: insert with position retry on conflict.
	const maxRetries = 3
	var position int64
	for attempt := 0; attempt < maxRetries; attempt++ {
		maxPos, err := b.store.GetMaxPosition(ctx)
		if err != nil {
			return nil, err
		}
		position = maxPos + 1

		rec := &store.BallotRecord{
			BallotID:        ballotID,
			EncryptedBallot: encryptedBallot,
			ZKProofs:        zkProofs,
			Position:        position,
			MerkleRootSHA:   "", // will be updated after tree append
		}
		err = b.store.InsertBallot(ctx, rec)
		if err == nil {
			break // success
		}
		if errors.Is(err, store.ErrDuplicateBallot) {
			return nil, ErrDuplicateBallot
		}
		if errors.Is(err, store.ErrPositionConflict) {
			if attempt == maxRetries-1 {
				return nil, ErrPositionConflict
			}
			continue // retry with new position
		}
		return nil, err
	}

	// Tree update only after DB confirms the insert.
	b.tree.Append(leafData)
	rootHash := b.tree.Root()
	root := hex.EncodeToString(rootHash[:])

	return &AppendResult{Position: position, MerkleRoot: root}, nil
}

// Inclusion is a Merkle inclusion proof together with the tree size and root
// it was computed against. The three are taken under one lock, so they always
// match each other.
type Inclusion struct {
	Proof    []merkle.Hash
	TreeSize uint64
	Root     merkle.Hash
}

// GetBallot retrieves a ballot and its Merkle inclusion proof against the
// current tree.
func (b *Board) GetBallot(ctx context.Context, ballotID string) (*store.BallotRecord, *Inclusion, error) {
	rec, err := b.store.GetBallot(ctx, ballotID)
	if err != nil {
		return nil, nil, err
	}
	if rec == nil {
		return nil, nil, nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	size := b.tree.Size()
	if rec.Position < 1 || uint64(rec.Position-1) >= size {
		return nil, nil, fmt.Errorf("ballot %q at position %d is not in the tree (size %d)", ballotID, rec.Position, size)
	}
	proof, err := b.tree.InclusionProof(uint64(rec.Position-1), size)
	if err != nil {
		return nil, nil, err
	}

	return rec, &Inclusion{Proof: proof, TreeSize: size, Root: b.tree.Root()}, nil
}

// Root returns the current Merkle root as hex string.
func (b *Board) Root() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tree.Size() == 0 {
		return ""
	}
	r := b.tree.Root()
	return hex.EncodeToString(r[:])
}

// Size returns the number of ballots.
func (b *Board) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return int(b.tree.Size())
}

// Seal marks the board as read-only. No more ballots can be appended.
// The sealed state is persisted to the database so it survives restarts.
func (b *Board) Seal(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.store.SetBoardState(ctx, "sealed", "true"); err != nil {
		return fmt.Errorf("persist sealed state: %w", err)
	}
	b.sealed = true
	return nil
}

// IsSealed returns whether the board is sealed.
func (b *Board) IsSealed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sealed
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
