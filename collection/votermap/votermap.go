package votermap

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// Store is the interface for voter ballot tracking.
// Implementations must be safe for concurrent use.
type Store interface {
	Record(ctx context.Context, egnHash, ballotID, channel string, timestamp int64) (prevBallotID string, err error)
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

// MemoryStore is an in-memory Store implementation for testing and development.
type MemoryStore struct {
	mu      sync.RWMutex
	mapping map[string]entry // egnHash -> entry
}

type entry struct {
	BallotID  string
	Channel   string // "online" or "in_person"
	Timestamp int64  // unix timestamp
}

// NewMemoryStore creates an empty in-memory Store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{mapping: make(map[string]entry)}
}

func (ms *MemoryStore) Record(_ context.Context, egnHash, ballotID, channel string, timestamp int64) (string, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	prev := ""
	if existing, ok := ms.mapping[egnHash]; ok {
		prev = existing.BallotID
	}
	ms.mapping[egnHash] = entry{
		BallotID:  ballotID,
		Channel:   channel,
		Timestamp: timestamp,
	}
	return prev, nil
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
