package ballot

import (
	"os"
	"testing"
)

func TestEnqueueAndPending(t *testing.T) {
	dir, _ := os.MkdirTemp("", "machine-test")
	defer os.RemoveAll(dir)

	q := NewQueue(dir)
	rec, err := q.Enqueue("ballot-001", []byte(`{"ct":"encrypted"}`), []byte(`{"proof":"zk"}`))
	if err != nil {
		t.Fatal(err)
	}
	if rec.BallotID != "ballot-001" {
		t.Fatalf("expected ballot-001, got %s", rec.BallotID)
	}
	if rec.EncryptedBallot == nil {
		t.Fatal("encrypted ballot should not be nil")
	}
	if rec.ZKProofs == nil {
		t.Fatal("zk proofs should not be nil")
	}

	pending := q.Pending()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}
}

func TestEnqueueRequiresBallotID(t *testing.T) {
	dir, _ := os.MkdirTemp("", "machine-test")
	defer os.RemoveAll(dir)

	q := NewQueue(dir)
	_, err := q.Enqueue("", nil, nil)
	if err == nil {
		t.Fatal("expected error for empty ballot ID")
	}
}

func TestMarkSynced(t *testing.T) {
	dir, _ := os.MkdirTemp("", "machine-test")
	defer os.RemoveAll(dir)

	q := NewQueue(dir)
	rec, _ := q.Enqueue("ballot-002", []byte(`enc`), []byte(`zk`))
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
	q.Enqueue("a", []byte(`enc`), []byte(`zk`))
	q.Enqueue("b", []byte(`enc`), []byte(`zk`))
	q.Enqueue("c", []byte(`enc`), []byte(`zk`))

	if q.Size() != 3 {
		t.Fatalf("expected 3, got %d", q.Size())
	}
}

func TestPersistence(t *testing.T) {
	dir, _ := os.MkdirTemp("", "machine-test")
	defer os.RemoveAll(dir)

	q := NewQueue(dir)
	rec, _ := q.Enqueue("ballot-persist", []byte(`enc`), []byte(`zk`))

	// Check file exists
	files, _ := os.ReadDir(dir)
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0].Name() != rec.BallotID+".json" {
		t.Fatalf("unexpected filename: %s", files[0].Name())
	}
}

func TestGenerateBallotID(t *testing.T) {
	id, err := GenerateBallotID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(id))
	}
}
