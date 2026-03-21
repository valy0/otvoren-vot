package session

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Session represents an active verification session.
type Session struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Verified  bool      `json:"verified"` // whether return code has been delivered
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

// Create creates a new session and returns its ID.
func (s *Store) Create() (*Session, error) {
	id, err := generateID()
	if err != nil {
		return nil, err
	}
	sess := &Session{
		ID:        id,
		CreatedAt: time.Now(),
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
