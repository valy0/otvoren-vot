package ballot

import (
	"os"
	"testing"
)

func TestEnqueueAndPending(t *testing.T) {
	dir, _ := os.MkdirTemp("", "machine-test")
	defer os.RemoveAll(dir)

	q := NewQueue(dir)
	rec, err := q.Enqueue(2, "123456")
	if err != nil {
		t.Fatal(err)
	}
	if rec.BallotID == "" {
		t.Fatal("ballot ID should not be empty")
	}
	if rec.PartyIndex != 2 {
		t.Fatalf("expected party 2, got %d", rec.PartyIndex)
	}

	pending := q.Pending()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}
}

func TestMarkSynced(t *testing.T) {
	dir, _ := os.MkdirTemp("", "machine-test")
	defer os.RemoveAll(dir)

	q := NewQueue(dir)
	rec, _ := q.Enqueue(0, "111111")
	q.MarkSynced(rec.BallotID)

	pending := q.Pending()
	if len(pending) != 0 {
		t.Fatalf("expected 0 pending after sync, got %d", len(pending))
	}
}

func TestQueueSize(t *testing.T) {
	dir, _ := os.MkdirTemp("", "machine-test")
	defer os.RemoveAll(dir)

	q := NewQueue(dir)
	q.Enqueue(0, "a")
	q.Enqueue(1, "b")
	q.Enqueue(2, "c")

	if q.Size() != 3 {
		t.Fatalf("expected 3, got %d", q.Size())
	}
}

func TestPersistence(t *testing.T) {
	dir, _ := os.MkdirTemp("", "machine-test")
	defer os.RemoveAll(dir)

	q := NewQueue(dir)
	rec, _ := q.Enqueue(1, "999999")

	// Check file exists
	files, _ := os.ReadDir(dir)
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0].Name() != rec.BallotID+".json" {
		t.Fatalf("unexpected filename: %s", files[0].Name())
	}
}
