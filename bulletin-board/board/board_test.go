package board

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/valy0/otvoren-vot/bulletin-board/store"
	"github.com/valy0/otvoren-vot/crypto/merkle"
)

func testDatabaseURL() string {
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		return url
	}
	return "postgres://board:dev@localhost:5432/bulletin_board?sslmode=disable"
}

func setupBoard(t *testing.T) *Board {
	t.Helper()
	ctx := context.Background()
	s, err := store.New(ctx, testDatabaseURL(), 25, 5)
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	s.RunMigrations(ctx)
	// Clean for test isolation (disable append-only triggers temporarily)
	s.Pool().Exec(ctx, "ALTER TABLE signed_roots DISABLE TRIGGER ALL")
	s.Pool().Exec(ctx, "ALTER TABLE ballots DISABLE TRIGGER ALL")
	s.Pool().Exec(ctx, "DELETE FROM signed_roots")
	s.Pool().Exec(ctx, "DELETE FROM ballots")
	s.Pool().Exec(ctx, "DELETE FROM board_state")
	s.Pool().Exec(ctx, "ALTER TABLE ballots ENABLE TRIGGER ALL")
	s.Pool().Exec(ctx, "ALTER TABLE signed_roots ENABLE TRIGGER ALL")
	s.RunMigrations(ctx) // re-seed board_state defaults
	t.Cleanup(func() { s.Close() })

	b, err := New(ctx, s)
	if err != nil {
		t.Fatalf("create board: %v", err)
	}
	return b
}

func TestAppendAndRetrieve(t *testing.T) {
	b := setupBoard(t)
	ctx := context.Background()

	result, err := b.AppendBallot(ctx, "ballot-1",
		json.RawMessage(`{"v":[1,0]}`),
		json.RawMessage(`{"p":[]}`))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if result.Position != 1 {
		t.Fatalf("expected position 1, got %d", result.Position)
	}
	if result.MerkleRoot == "" {
		t.Fatal("root should not be empty")
	}

	rec, proof, err := b.GetBallot(ctx, "ballot-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if rec == nil {
		t.Fatal("ballot should exist")
	}

	// Verify Merkle proof
	leafData := EncodeLeaf("ballot-1", json.RawMessage(`{"v":[1,0]}`), json.RawMessage(`{"p":[]}`))
	rootBytes, _ := hex.DecodeString(b.Root())
	if !merkle.VerifyInclusion(rootBytes, leafData, 0, b.Size(), proof) {
		t.Fatal("Merkle inclusion proof should verify")
	}
}

func TestAppendMultiple(t *testing.T) {
	b := setupBoard(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("ballot-%d", i)
		_, err := b.AppendBallot(ctx, id,
			json.RawMessage(`{}`), json.RawMessage(`{}`))
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	if b.Size() != 10 {
		t.Fatalf("expected 10, got %d", b.Size())
	}
}

func TestDuplicateRejected(t *testing.T) {
	b := setupBoard(t)
	ctx := context.Background()

	b.AppendBallot(ctx, "dup", json.RawMessage(`{}`), json.RawMessage(`{}`))
	_, err := b.AppendBallot(ctx, "dup", json.RawMessage(`{}`), json.RawMessage(`{}`))
	if !errors.Is(err, ErrDuplicateBallot) {
		t.Fatalf("expected ErrDuplicateBallot, got %v", err)
	}
}

func TestSealPreventsAppend(t *testing.T) {
	b := setupBoard(t)
	ctx := context.Background()

	if err := b.Seal(ctx); err != nil {
		t.Fatalf("seal: %v", err)
	}
	_, err := b.AppendBallot(ctx, "after-seal", json.RawMessage(`{}`), json.RawMessage(`{}`))
	if !errors.Is(err, ErrBoardSealed) {
		t.Fatalf("expected ErrBoardSealed, got %v", err)
	}
}

func TestSealPersistsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	s, err := store.New(ctx, testDatabaseURL(), 25, 5)
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	s.RunMigrations(ctx)
	s.Pool().Exec(ctx, "ALTER TABLE signed_roots DISABLE TRIGGER ALL")
	s.Pool().Exec(ctx, "ALTER TABLE ballots DISABLE TRIGGER ALL")
	s.Pool().Exec(ctx, "DELETE FROM signed_roots")
	s.Pool().Exec(ctx, "DELETE FROM ballots")
	s.Pool().Exec(ctx, "DELETE FROM board_state")
	s.Pool().Exec(ctx, "ALTER TABLE ballots ENABLE TRIGGER ALL")
	s.Pool().Exec(ctx, "ALTER TABLE signed_roots ENABLE TRIGGER ALL")
	s.RunMigrations(ctx) // re-seed board_state defaults
	t.Cleanup(func() { s.Close() })

	// Create board, seal it
	b1, err := New(ctx, s)
	if err != nil {
		t.Fatalf("create board: %v", err)
	}
	if b1.IsSealed() {
		t.Fatal("board should not be sealed initially")
	}
	if err := b1.Seal(ctx); err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Simulate restart: create a new Board from the same store
	b2, err := New(ctx, s)
	if err != nil {
		t.Fatalf("create board after restart: %v", err)
	}
	if !b2.IsSealed() {
		t.Fatal("board should still be sealed after restart")
	}

	// Verify appends are still blocked
	_, err = b2.AppendBallot(ctx, "post-restart", json.RawMessage(`{}`), json.RawMessage(`{}`))
	if !errors.Is(err, ErrBoardSealed) {
		t.Fatalf("expected ErrBoardSealed after restart, got %v", err)
	}
}
