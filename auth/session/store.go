// Package session provides Redis-backed voter session management.
//
// Each voter (identified by EGN) may hold at most one active session.
// Creating a new session atomically revokes any previous session for
// the same EGN, preventing two valid sessions from coexisting.
package session

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	// SessionTTL is how long a voter session remains valid.
	SessionTTL = 30 * time.Minute

	// egnKeyTTL is slightly longer than SessionTTL to prevent the EGN
	// mapping from expiring before the session it points to.
	egnKeyTTL = 30*time.Minute + 30*time.Second

	sessionPrefix = "session:"
	egnPrefix     = "egn:"
)

// ErrSessionNotFound is returned when resolving a session ID that does
// not exist or has expired.
var ErrSessionNotFound = fmt.Errorf("session not found")

// Store manages voter sessions.
type Store interface {
	// Create creates a new session for the given EGN. If a previous
	// session exists for the same EGN, it is atomically revoked.
	// Returns the new session ID.
	Create(ctx context.Context, egn string) (string, error)

	// Resolve looks up the EGN associated with a session ID.
	// Returns ErrSessionNotFound if the session does not exist.
	Resolve(ctx context.Context, sessionID string) (string, error)
}

// RedisStore implements Store backed by Redis.
type RedisStore struct {
	client *redis.Client
}

// NewRedisStore returns a Store backed by the given Redis client.
func NewRedisStore(client *redis.Client) *RedisStore {
	return &RedisStore{client: client}
}

// replaceSessionScript atomically replaces any existing session for an EGN.
//
//	KEYS[1] = EGN
//	ARGV[1] = new session UUID
//	ARGV[2] = session TTL in seconds
//	ARGV[3] = EGN key TTL in seconds
//
// It deletes the old session (if any), then creates the new session->EGN
// and EGN->session mappings with appropriate TTLs.
var replaceSessionScript = redis.NewScript(`
	local old_uuid = redis.call('GET', 'egn:' .. KEYS[1])
	if old_uuid then
		redis.call('DEL', 'session:' .. old_uuid)
	end
	redis.call('SET', 'session:' .. ARGV[1], KEYS[1], 'EX', ARGV[2])
	redis.call('SET', 'egn:' .. KEYS[1], ARGV[1], 'EX', ARGV[3])
	return 1
`)

// Create creates a new session for the voter identified by egn.
// Any previous session for the same EGN is atomically revoked.
func (s *RedisStore) Create(ctx context.Context, egn string) (string, error) {
	sessionID := uuid.New().String()
	sessionTTLSec := int(SessionTTL.Seconds())
	egnTTLSec := int(egnKeyTTL.Seconds())

	err := replaceSessionScript.Run(ctx, s.client, []string{egn}, sessionID, sessionTTLSec, egnTTLSec).Err()
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	return sessionID, nil
}

// Resolve returns the EGN associated with the given session ID.
// Returns ErrSessionNotFound if the session does not exist or has expired.
func (s *RedisStore) Resolve(ctx context.Context, sessionID string) (string, error) {
	egn, err := s.client.Get(ctx, sessionPrefix+sessionID).Result()
	if err == redis.Nil {
		return "", ErrSessionNotFound
	}
	if err != nil {
		return "", fmt.Errorf("resolve session: %w", err)
	}
	return egn, nil
}
