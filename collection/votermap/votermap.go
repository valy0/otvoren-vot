package votermap

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Store is the interface for voter ballot tracking.
// Implementations must be safe for concurrent use.
type Store interface {
	Record(ctx context.Context, egnHash, ballotID string, channel Channel, submittedAt time.Time) (prevBallotID string, err error)
	GetActiveBallotID(ctx context.Context, egnHash string) (string, bool, error)
	ActiveSet(ctx context.Context) ([]string, error)
	Size(ctx context.Context) (int, error)
	HasVoted(ctx context.Context, egnHash string) (bool, error)
}

// HashEGN returns a hex-encoded HMAC-SHA256 of the raw EGN using a
// deployment-specific key. The keyed hash prevents brute-force reversal
// over the small EGN keyspace (~tens of millions 10-digit numbers).
func HashEGN(egn string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(egn))
	return hex.EncodeToString(mac.Sum(nil))
}

// Channel represents the submission channel.
type Channel string

const (
	ChannelOnline   Channel = "online"
	ChannelInPerson Channel = "in_person"
)

// HistoryEntry represents one ballot submission in a voter's override chain.
type HistoryEntry struct {
	BallotID    string
	Channel     Channel
	SubmittedAt time.Time
	Seq         int
	RowHash     string // hex-encoded HMAC-SHA256
}

// OverrideChain represents the full submission history for one voter.
type OverrideChain struct {
	EgnHash     string
	Submissions []HistoryEntry
}

// ActiveBallotID returns the ballot ID of the most recent submission.
func (c OverrideChain) ActiveBallotID() string {
	if len(c.Submissions) == 0 {
		return ""
	}
	return c.Submissions[len(c.Submissions)-1].BallotID
}

// AuditStore provides read-only access to vote override history.
// All methods are scoped to the election_id configured at construction time.
type AuditStore interface {
	GetOverrideHistory(ctx context.Context, egnHash string) ([]HistoryEntry, error)
	GetAllOverrideChains(ctx context.Context, fn func(OverrideChain) error) error
}

// ComputeRowHash produces the tamper-detection hash for a history row.
// Uses null-byte delimiters to prevent field concatenation ambiguity.
func ComputeRowHash(key []byte, prevHash, egnHash, ballotID string, seq int) string {
	data := fmt.Appendf(nil, "%s\x00%s\x00%s\x00%d", prevHash, egnHash, ballotID, seq)
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// MemoryStore is an in-memory Store implementation for testing and development.
type MemoryStore struct {
	mu             sync.RWMutex
	mapping        map[string]entry
	history        map[string][]HistoryEntry
	historyHMACKey []byte
}

type entry struct {
	BallotID    string
	Channel     Channel
	SubmittedAt time.Time
}

// NewMemoryStore creates an empty in-memory Store.
func NewMemoryStore(historyHMACKey []byte) *MemoryStore {
	return &MemoryStore{
		mapping:        make(map[string]entry),
		history:        make(map[string][]HistoryEntry),
		historyHMACKey: historyHMACKey,
	}
}

func (ms *MemoryStore) Record(_ context.Context, egnHash, ballotID string, channel Channel, submittedAt time.Time) (string, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	prev := ""
	if existing, ok := ms.mapping[egnHash]; ok {
		prev = existing.BallotID
	}
	ms.mapping[egnHash] = entry{
		BallotID:    ballotID,
		Channel:     channel,
		SubmittedAt: submittedAt,
	}

	// Append to history
	prevHash := ""
	entries := ms.history[egnHash]
	if len(entries) > 0 {
		prevHash = entries[len(entries)-1].RowHash
	}
	nextSeq := len(entries) + 1
	rowHash := ComputeRowHash(ms.historyHMACKey, prevHash, egnHash, ballotID, nextSeq)
	ms.history[egnHash] = append(entries, HistoryEntry{
		BallotID:    ballotID,
		Channel:     channel,
		SubmittedAt: submittedAt,
		Seq:         nextSeq,
		RowHash:     rowHash,
	})

	return prev, nil
}

// GetOverrideHistory returns the full submission history for a voter.
func (ms *MemoryStore) GetOverrideHistory(_ context.Context, egnHash string) ([]HistoryEntry, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	entries := ms.history[egnHash]
	if len(entries) == 0 {
		return nil, nil
	}
	result := make([]HistoryEntry, len(entries))
	copy(result, entries)
	return result, nil
}

// GetAllOverrideChains iterates over all voters with >= 2 submissions (overrides).
func (ms *MemoryStore) GetAllOverrideChains(_ context.Context, fn func(OverrideChain) error) error {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	for egnHash, entries := range ms.history {
		if len(entries) < 2 {
			continue
		}
		chain := OverrideChain{
			EgnHash:     egnHash,
			Submissions: make([]HistoryEntry, len(entries)),
		}
		copy(chain.Submissions, entries)
		if err := fn(chain); err != nil {
			return err
		}
	}
	return nil
}

func (ms *MemoryStore) GetActiveBallotID(_ context.Context, egnHash string) (string, bool, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	e, ok := ms.mapping[egnHash]
	if !ok {
		return "", false, nil
	}
	return e.BallotID, true, nil
}

func (ms *MemoryStore) ActiveSet(_ context.Context) ([]string, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	ids := make([]string, 0, len(ms.mapping))
	for _, e := range ms.mapping {
		ids = append(ids, e.BallotID)
	}
	return ids, nil
}

func (ms *MemoryStore) Size(_ context.Context) (int, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	return len(ms.mapping), nil
}

func (ms *MemoryStore) HasVoted(_ context.Context, egnHash string) (bool, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	_, ok := ms.mapping[egnHash]
	return ok, nil
}
