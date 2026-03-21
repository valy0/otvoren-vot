package ballot

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Record represents a locally queued ballot.
type Record struct {
	BallotID    string    `json:"ballot_id"`
	PartyIndex  int       `json:"party_index"`
	SessionCode string    `json:"session_code"`
	CreatedAt   time.Time `json:"created_at"`
	Synced      bool      `json:"synced"`
}

// Queue manages locally stored ballots for offline operation.
type Queue struct {
	mu      sync.Mutex
	records []*Record
	dataDir string
}

// NewQueue creates a ballot queue with persistent storage.
func NewQueue(dataDir string) *Queue {
	os.MkdirAll(dataDir, 0700)
	return &Queue{dataDir: dataDir}
}

// Enqueue adds a ballot to the local queue.
func (q *Queue) Enqueue(partyIndex int, sessionCode string) (*Record, error) {
	id, err := generateBallotID()
	if err != nil {
		return nil, err
	}

	rec := &Record{
		BallotID:    id,
		PartyIndex:  partyIndex,
		SessionCode: sessionCode,
		CreatedAt:   time.Now(),
	}

	q.mu.Lock()
	q.records = append(q.records, rec)
	q.mu.Unlock()

	// Persist to disk
	if err := q.persist(rec); err != nil {
		return nil, fmt.Errorf("persist ballot: %w", err)
	}

	return rec, nil
}

// Pending returns all unsynced ballots.
func (q *Queue) Pending() []*Record {
	q.mu.Lock()
	defer q.mu.Unlock()
	var pending []*Record
	for _, r := range q.records {
		if !r.Synced {
			pending = append(pending, r)
		}
	}
	return pending
}

// MarkSynced marks a ballot as synced.
func (q *Queue) MarkSynced(ballotID string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, r := range q.records {
		if r.BallotID == ballotID {
			r.Synced = true
		}
	}
}

// Size returns the total number of ballots.
func (q *Queue) Size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.records)
}

func (q *Queue) persist(rec *Record) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	path := filepath.Join(q.dataDir, rec.BallotID+".json")
	return os.WriteFile(path, data, 0600)
}

func generateBallotID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
