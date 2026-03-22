package session

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"filippo.io/edwards25519"
)

// Session represents an active verification session.
type Session struct {
	ID           string                       `json:"id"`
	CreatedAt    time.Time                    `json:"created_at"`
	Verified     bool                         `json:"verified"` // whether return code has been delivered
	Shares       map[int]*edwards25519.Scalar // trustee_index -> share
	MasterSecret *edwards25519.Scalar         // kept for return code derivation, zeroed at expiry
	ThresholdMet bool
	Codes        map[string]string // party -> 8-digit code
	Threshold    int
}

// Store manages verification sessions.
// In production, sessions are identified by blinded tokens (RFC 9474).
// For development, we use simple random session IDs.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewStore creates an empty session store.
func NewStore() *Store {
	return &Store{sessions: make(map[string]*Session)}
}

// Create creates a new session with the given threshold and returns it.
func (s *Store) Create(threshold int) (*Session, error) {
	id, err := generateID()
	if err != nil {
		return nil, err
	}
	sess := &Session{
		ID:        id,
		CreatedAt: time.Now(),
		Shares:    make(map[int]*edwards25519.Scalar),
		Threshold: threshold,
	}
	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
	return sess, nil
}

// Get retrieves a session by ID.
func (s *Store) Get(id string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

// AddShare adds a trustee's key share to a session.
// Returns the number of shares received and whether the threshold has been newly met.
// Idempotent: if the trustee already submitted, returns the current count without error.
func (s *Store) AddShare(sessionID string, trusteeIndex int, share *edwards25519.Scalar) (sharesReceived int, thresholdMet bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sessionID]
	if !ok {
		return 0, false, errors.New("session not found")
	}
	if sess.ThresholdMet {
		return len(sess.Shares), true, nil
	}

	// Idempotent: if this trustee already submitted, return current state
	if _, exists := sess.Shares[trusteeIndex]; exists {
		return len(sess.Shares), sess.ThresholdMet, nil
	}

	sess.Shares[trusteeIndex] = share
	count := len(sess.Shares)
	met := count >= sess.Threshold
	sess.ThresholdMet = met
	return count, met, nil
}

// SetCodes stores the generated codes and master secret on the session.
func (s *Store) SetCodes(sessionID string, codes map[string]string, masterSecret *edwards25519.Scalar) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return
	}
	sess.Codes = codes
	sess.MasterSecret = masterSecret
}

// Close zeros the master secret and individual shares for a session.
func (s *Store) Close(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return
	}
	// Zero master secret
	if sess.MasterSecret != nil {
		zero := edwards25519.NewScalar()
		sess.MasterSecret.Set(zero)
		sess.MasterSecret = nil
	}
	// Zero individual shares
	zero := edwards25519.NewScalar()
	for idx, share := range sess.Shares {
		share.Set(zero)
		delete(sess.Shares, idx)
	}
}

// MarkVerified marks a session as having delivered the return code.
func (s *Store) MarkVerified(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return false
	}
	sess.Verified = true
	return true
}

// Count returns the number of active sessions.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
