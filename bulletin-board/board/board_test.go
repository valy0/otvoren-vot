package board

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/valy0/otvoren-vot/bulletin-board/internal/testdb"
	"github.com/valy0/otvoren-vot/bulletin-board/store"
	"github.com/valy0/otvoren-vot/crypto/merkle"
)

func setupBoard(t *testing.T) *Board {
	t.Helper()
	ctx := context.Background()
	s, err := store.New(ctx, testdb.URL(), 25, 5)
	if err != nil {
		testdb.Unavailable(t, err)
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

	rec, inc, err := b.GetBallot(ctx, "ballot-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if rec == nil {
		t.Fatal("ballot should exist")
	}

	// Verify Merkle proof
	leafData := EncodeLeaf("ballot-1", json.RawMessage(`{"v":[1,0]}`), json.RawMessage(`{"p":[]}`))
	if err := merkle.VerifyInclusion(merkle.LeafHash(leafData), uint64(rec.Position-1), inc.TreeSize, inc.Proof, inc.Root); err != nil {
		t.Fatalf("Merkle inclusion proof should verify: %v", err)
	}
	if hex.EncodeToString(inc.Root[:]) != b.Root() {
		t.Fatalf("inclusion root %x != board root %s", inc.Root, b.Root())
	}
}

func TestGetBallotProofAfterLaterAppends(t *testing.T) {
	b := setupBoard(t)
	ctx := context.Background()

	enc, zk := json.RawMessage(`{"v":[1,0]}`), json.RawMessage(`{"p":[]}`)
	for i := 1; i <= 3; i++ {
		if _, err := b.AppendBallot(ctx, fmt.Sprintf("b-%d", i), enc, zk); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	leaf := merkle.LeafHash(EncodeLeaf("b-1", enc, zk))

	check := func(wantSize uint64) {
		t.Helper()
		rec, inc, err := b.GetBallot(ctx, "b-1")
		if err != nil || rec == nil {
			t.Fatalf("get: rec=%v err=%v", rec, err)
		}
		if inc.TreeSize != wantSize {
			t.Fatalf("tree size = %d, want %d", inc.TreeSize, wantSize)
		}
		if hex.EncodeToString(inc.Root[:]) != b.Root() {
			t.Fatalf("inclusion root %x != board root %s", inc.Root, b.Root())
		}
		if err := merkle.VerifyInclusion(leaf, uint64(rec.Position-1), inc.TreeSize, inc.Proof, inc.Root); err != nil {
			t.Fatalf("proof at size %d does not verify: %v", wantSize, err)
		}
	}
	check(3)
	if _, err := b.AppendBallot(ctx, "b-4", enc, zk); err != nil {
		t.Fatalf("append 4: %v", err)
	}
	check(4)
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
	s, err := store.New(ctx, testdb.URL(), 25, 5)
	if err != nil {
		testdb.Unavailable(t, err)
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
