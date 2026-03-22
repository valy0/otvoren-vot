package session

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/redis/go-redis/v9"
)

// testRedisClient returns a Redis client connected to a test instance.
// It skips the test if Redis is unavailable. The database is flushed
// after each test via t.Cleanup.
func testRedisClient(t *testing.T) *redis.Client {
	t.Helper()

	addr := "localhost:6379"
	if url := os.Getenv("TEST_REDIS_URL"); url != "" {
		addr = url
	}

	client := redis.NewClient(&redis.Options{Addr: addr})
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Skipf("Redis not available at %s: %v", addr, err)
	}

	t.Cleanup(func() {
		client.FlushDB(context.Background())
		client.Close()
	})

	return client
}

func TestCreateAndResolve(t *testing.T) {
	client := testRedisClient(t)
	store := NewRedisStore(client)
	ctx := context.Background()

	sessionID, err := store.Create(ctx, "8501011234")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sessionID == "" {
		t.Fatal("expected non-empty session ID")
	}

	egn, err := store.Resolve(ctx, sessionID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if egn != "8501011234" {
		t.Fatalf("expected EGN 8501011234, got %s", egn)
	}
}

func TestResolveNotFound(t *testing.T) {
	client := testRedisClient(t)
	store := NewRedisStore(client)
	ctx := context.Background()

	_, err := store.Resolve(ctx, "nonexistent-uuid")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestCreateRevokesOld(t *testing.T) {
	client := testRedisClient(t)
	store := NewRedisStore(client)
	ctx := context.Background()

	// First session for this EGN.
	oldID, err := store.Create(ctx, "9001015678")
	if err != nil {
		t.Fatalf("Create (first): %v", err)
	}

	// Second session for the same EGN should revoke the first.
	newID, err := store.Create(ctx, "9001015678")
	if err != nil {
		t.Fatalf("Create (second): %v", err)
	}

	if oldID == newID {
		t.Fatal("expected different session IDs")
	}

	// Old session must no longer resolve.
	_, err = store.Resolve(ctx, oldID)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("old session should be revoked, got %v", err)
	}

	// New session must resolve correctly.
	egn, err := store.Resolve(ctx, newID)
	if err != nil {
		t.Fatalf("Resolve (new): %v", err)
	}
	if egn != "9001015678" {
		t.Fatalf("expected EGN 9001015678, got %s", egn)
	}
}

func TestRateLimiterAllow(t *testing.T) {
	client := testRedisClient(t)
	rl := NewRateLimiter(client)
	ctx := context.Background()

	egn := "7501019999"

	// First 5 calls should be allowed.
	for i := range 5 {
		allowed, err := rl.Allow(ctx, egn)
		if err != nil {
			t.Fatalf("Allow call %d: %v", i+1, err)
		}
		if !allowed {
			t.Fatalf("call %d should be allowed", i+1)
		}
	}

	// 6th call should be rejected.
	allowed, err := rl.Allow(ctx, egn)
	if err != nil {
		t.Fatalf("Allow call 6: %v", err)
	}
	if allowed {
		t.Fatal("6th call should be rate-limited")
	}
}

func TestRateLimiterDifferentEGNs(t *testing.T) {
	client := testRedisClient(t)
	rl := NewRateLimiter(client)
	ctx := context.Background()

	// Exhaust the limit for EGN A.
	for range 5 {
		if _, err := rl.Allow(ctx, "egnA"); err != nil {
			t.Fatalf("Allow egnA: %v", err)
		}
	}

	// EGN B should still be allowed.
	allowed, err := rl.Allow(ctx, "egnB")
	if err != nil {
		t.Fatalf("Allow egnB: %v", err)
	}
	if !allowed {
		t.Fatal("egnB should not be rate-limited by egnA's usage")
	}
}
