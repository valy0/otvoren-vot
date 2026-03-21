package votermap

import "sync"

// VoterMap tracks which ballot ID is active for each voter (by EGN).
// This is the core data structure for deduplication and bidirectional override.
type VoterMap struct {
	mu      sync.RWMutex
	mapping map[string]entry // EGN -> entry
}

type entry struct {
	BallotID  string
	Channel   string // "online" or "in-person"
	Timestamp int64  // unix timestamp
}

// New creates an empty VoterMap.
func New() *VoterMap {
	return &VoterMap{mapping: make(map[string]entry)}
}

// Record records or updates a voter's active ballot.
// If the voter already has a ballot, the new one replaces it (override).
// Returns the previous ballot ID (empty if first vote).
func (vm *VoterMap) Record(egn, ballotID, channel string, timestamp int64) string {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	prev := ""
	if existing, ok := vm.mapping[egn]; ok {
		prev = existing.BallotID
	}
	vm.mapping[egn] = entry{
		BallotID:  ballotID,
		Channel:   channel,
		Timestamp: timestamp,
	}
	return prev
}

// GetActiveBallotID returns the current active ballot ID for a voter.
func (vm *VoterMap) GetActiveBallotID(egn string) (string, bool) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	e, ok := vm.mapping[egn]
	if !ok {
		return "", false
	}
	return e.BallotID, true
}

// ActiveSet returns all active ballot IDs (one per voter).
// This is used at polls close for deduplication.
func (vm *VoterMap) ActiveSet() []string {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	ids := make([]string, 0, len(vm.mapping))
	for _, e := range vm.mapping {
		ids = append(ids, e.BallotID)
	}
	return ids
}

// Size returns the number of unique voters who have voted.
func (vm *VoterMap) Size() int {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return len(vm.mapping)
}

// HasVoted returns whether a voter has already voted.
func (vm *VoterMap) HasVoted(egn string) bool {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	_, ok := vm.mapping[egn]
	return ok
}
