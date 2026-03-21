package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func testDatabaseURL() string {
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		return url
	}
	return "postgres://board:dev@localhost:5432/bulletin_board?sslmode=disable"
}

func setupStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	s, err := New(ctx, testDatabaseURL())
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	if err := s.RunMigrations(ctx); err != nil {
		t.Fatalf("migrations failed: %v", err)
	}
	// Clean tables for test isolation
	s.pool.Exec(ctx, "DELETE FROM signed_roots")
	s.pool.Exec(ctx, "DELETE FROM ballots")
	t.Cleanup(func() { s.Close() })
	return s
}

func TestInsertAndGetBallot(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()

	rec := &BallotRecord{
		BallotID:        "test-ballot-1",
		EncryptedBallot: json.RawMessage(`{"party_vector": [1,0,0]}`),
		ZKProofs:        json.RawMessage(`{"binary_proofs": []}`),
		Position:        1,
		MerkleRootSHA:   "abc123",
	}
	if err := s.InsertBallot(ctx, rec); err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, err := s.GetBallot(ctx, "test-ballot-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("ballot should exist")
	}
	if got.Position != 1 {
		t.Fatalf("expected position 1, got %d", got.Position)
	}
}

func TestGetBallotNotFound(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()

	got, err := s.GetBallot(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatal("should return nil for nonexistent ballot")
	}
}

func TestListBallotsPaginated(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		s.InsertBallot(ctx, &BallotRecord{
			BallotID:        fmt.Sprintf("ballot-%d", i),
			EncryptedBallot: json.RawMessage(`{}`),
			ZKProofs:        json.RawMessage(`{}`),
			Position:        int64(i),
			MerkleRootSHA:   "root",
		})
	}

	// First page: 3 records
	page1, err := s.ListBallots(ctx, 0, 3)
	if err != nil {
		t.Fatalf("list page 1: %v", err)
	}
	if len(page1) != 3 {
		t.Fatalf("expected 3, got %d", len(page1))
	}

	// Second page: remaining 2
	page2, err := s.ListBallots(ctx, page1[2].Position, 3)
	if err != nil {
		t.Fatalf("list page 2: %v", err)
	}
	if len(page2) != 2 {
		t.Fatalf("expected 2, got %d", len(page2))
	}
}

func TestBallotCount(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()

	count, _ := s.GetBallotCount(ctx)
	if count != 0 {
		t.Fatalf("expected 0, got %d", count)
	}

	s.InsertBallot(ctx, &BallotRecord{
		BallotID: "b1", EncryptedBallot: json.RawMessage(`{}`),
		ZKProofs: json.RawMessage(`{}`), Position: 1, MerkleRootSHA: "r",
	})

	count, _ = s.GetBallotCount(ctx)
	if count != 1 {
		t.Fatalf("expected 1, got %d", count)
	}
}

func TestSignedRoots(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()

	err := s.InsertSignedRoot(ctx, &SignedRootRecord{
		RootSHA256:  "root1",
		BallotCount: 100,
		Signature:   "sig1",
	})
	if err != nil {
		t.Fatalf("insert root: %v", err)
	}

	got, err := s.GetLatestSignedRoot(ctx)
	if err != nil {
		t.Fatalf("get root: %v", err)
	}
	if got == nil {
		t.Fatal("should have a root")
	}
	if got.RootSHA256 != "root1" || got.BallotCount != 100 {
		t.Fatalf("unexpected root: %+v", got)
	}
}
