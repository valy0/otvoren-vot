package session

import (
	"crypto/rand"
	"testing"
	"time"

	"filippo.io/edwards25519"
)

// randomScalar generates a cryptographically random scalar for testing.
func randomScalar() *edwards25519.Scalar {
	var buf [64]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	s, err := edwards25519.NewScalar().SetUniformBytes(buf[:])
	if err != nil {
		panic("SetUniformBytes failed: " + err.Error())
	}
	return s
}

func TestCreateAndGet(t *testing.T) {
	s := NewStore()
	sess, err := s.Create(3)
	if err != nil {
		t.Fatal(err)
	}
	if sess.ID == "" {
		t.Fatal("session ID should not be empty")
	}
	if sess.Threshold != 3 {
		t.Fatalf("expected threshold 3, got %d", sess.Threshold)
	}

	got, ok := s.Get(sess.ID)
	if !ok {
		t.Fatal("session should exist")
	}
	if got.Verified {
		t.Fatal("new session should not be verified")
	}
	if got.ThresholdMet {
		t.Fatal("new session should not have threshold met")
	}
}

func TestGetNonexistent(t *testing.T) {
	s := NewStore()
	_, ok := s.Get("nonexistent")
	if ok {
		t.Fatal("nonexistent session should return false")
	}
}

func TestAddShareAndThreshold(t *testing.T) {
	s := NewStore()
	sess, _ := s.Create(3)

	// Add 3 shares to reach threshold
	for i := 1; i <= 3; i++ {
		share := randomScalar()
		count, met, err := s.AddShare(sess.ID, i, share)
		if err != nil {
			t.Fatalf("AddShare(%d) error: %v", i, err)
		}
		if count != i {
			t.Fatalf("expected count %d, got %d", i, count)
		}
		if i < 3 && met {
			t.Fatalf("threshold should not be met with %d shares", i)
		}
		if i == 3 && !met {
			t.Fatal("threshold should be met with 3 shares")
		}
	}
}

func TestAddShareIdempotent(t *testing.T) {
	s := NewStore()
	sess, _ := s.Create(3)

	share := randomScalar()
	count1, _, err := s.AddShare(sess.ID, 1, share)
	if err != nil {
		t.Fatal(err)
	}

	// Submit same trustee index again
	count2, _, err := s.AddShare(sess.ID, 1, share)
	if err != nil {
		t.Fatal(err)
	}
	if count1 != count2 {
		t.Fatalf("idempotent submit should return same count: %d vs %d", count1, count2)
	}
}

func TestAddShareNonexistentSession(t *testing.T) {
	s := NewStore()
	share := randomScalar()
	_, _, err := s.AddShare("nonexistent", 1, share)
	if err == nil {
		t.Fatal("expected error for nonexistent session")
	}
}

func TestSetCodes(t *testing.T) {
	s := NewStore()
	sess, _ := s.Create(3)

	codes := map[string]string{"ГЕРБ": "12345678", "ПП-ДБ": "87654321"}
	secret := randomScalar()
	s.SetCodes(sess.ID, codes, secret)

	got, _ := s.Get(sess.ID)
	if len(got.Codes) != 2 {
		t.Fatalf("expected 2 codes, got %d", len(got.Codes))
	}
	if got.Codes["ГЕРБ"] != "12345678" {
		t.Fatalf("unexpected code for ГЕРБ: %s", got.Codes["ГЕРБ"])
	}
	if got.MasterSecret == nil {
		t.Fatal("master secret should be set")
	}
}

func TestClose(t *testing.T) {
	s := NewStore()
	sess, _ := s.Create(3)

	secret := randomScalar()
	s.SetCodes(sess.ID, map[string]string{"ГЕРБ": "12345678"}, secret)
	s.AddShare(sess.ID, 1, randomScalar())

	s.Close(sess.ID)

	got, _ := s.Get(sess.ID)
	if got.MasterSecret != nil {
		t.Fatal("master secret should be nil after close")
	}
	if len(got.Shares) != 0 {
		t.Fatalf("shares should be empty after close, got %d", len(got.Shares))
	}
}

func TestMarkVerified(t *testing.T) {
	s := NewStore()
	sess, _ := s.Create(3)

	if !s.MarkVerified(sess.ID) {
		t.Fatal("should mark existing session")
	}
	got, _ := s.Get(sess.ID)
	if !got.Verified {
		t.Fatal("session should be verified")
	}
}

func TestMarkVerifiedNonexistent(t *testing.T) {
	s := NewStore()
	if s.MarkVerified("nope") {
		t.Fatal("should return false for nonexistent session")
	}
}

func TestCount(t *testing.T) {
	s := NewStore()
	if s.Count() != 0 {
		t.Fatal("empty store should have count 0")
	}
	s.Create(3)
	s.Create(3)
	if s.Count() != 2 {
		t.Fatalf("expected 2, got %d", s.Count())
	}
}

func TestGetExpiredSession(t *testing.T) {
	s := NewStore()
	sess, err := s.Create(3)
	if err != nil {
		t.Fatal(err)
	}

	// Manually set expiry to the past.
	s.mu.Lock()
	sess.ExpiresAt = time.Now().Add(-1 * time.Minute)
	s.mu.Unlock()

	_, ok := s.Get(sess.ID)
	if ok {
		t.Fatal("expired session should not be returned by Get")
	}
}

func TestCleanupRemovesExpired(t *testing.T) {
	s := NewStore()
	sess, err := s.Create(3)
	if err != nil {
		t.Fatal(err)
	}

	// Set a master secret so we can verify it gets zeroed.
	secret := randomScalar()
	s.SetCodes(sess.ID, map[string]string{"ГЕРБ": "12345678"}, secret)

	// Expire the session.
	s.mu.Lock()
	sess.ExpiresAt = time.Now().Add(-1 * time.Minute)
	s.mu.Unlock()

	// Start cleanup with a very short interval.
	s.StartCleanup(10 * time.Millisecond)
	defer s.Stop()

	// Wait for the cleanup goroutine to run.
	time.Sleep(50 * time.Millisecond)

	if s.Count() != 0 {
		t.Fatalf("expected 0 sessions after cleanup, got %d", s.Count())
	}
}

// Verify that edwards25519.Scalar.Set works as expected for zeroing.
func TestScalarZeroing(t *testing.T) {
	secret := randomScalar()
	zero := edwards25519.NewScalar()
	secret.Set(zero)
	if secret.Equal(zero) != 1 {
		t.Fatal("scalar should be zero after Set(zero)")
	}
}
