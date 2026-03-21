package session

import "testing"

func TestCreateAndGet(t *testing.T) {
	s := NewStore()
	sess, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}
	if sess.ID == "" {
		t.Fatal("session ID should not be empty")
	}

	got, ok := s.Get(sess.ID)
	if !ok {
		t.Fatal("session should exist")
	}
	if got.Verified {
		t.Fatal("new session should not be verified")
	}
}

func TestGetNonexistent(t *testing.T) {
	s := NewStore()
	_, ok := s.Get("nonexistent")
	if ok {
		t.Fatal("nonexistent session should return false")
	}
}

func TestMarkVerified(t *testing.T) {
	s := NewStore()
	sess, _ := s.Create()

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
	s.Create()
	s.Create()
	if s.Count() != 2 {
		t.Fatalf("expected 2, got %d", s.Count())
	}
}
