package store_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/valy0/otvoren-vot/collection/store"
	"github.com/valy0/otvoren-vot/collection/votermap"
)

var testHistoryKey = []byte("test-history-key")

func testDatabaseURL() string {
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		return url
	}
	return "postgres://collection:dev@localhost:5433/collection?sslmode=disable"
}

func randomElectionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func setupStore(t *testing.T) *store.PostgresStore {
	t.Helper()
	ctx := context.Background()
	electionID := randomElectionID()

	s, err := store.New(ctx, testDatabaseURL(), electionID, testHistoryKey)
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	if err := s.RunMigrations(ctx); err != nil {
		t.Fatalf("migrations failed: %v", err)
	}

	t.Cleanup(func() { s.Close() })
	return s
}

func TestPostgresStore(t *testing.T) {
	ctx := context.Background()

	t.Run("RecordNew", func(t *testing.T) {
		s := setupStore(t)
		prev, err := s.Record(ctx, "hash-alice", "ballot-1", votermap.ChannelOnline, time.Unix(1700000000, 0))
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
		if prev != "" {
			t.Fatalf("expected empty prev for new voter, got %q", prev)
		}
	})

	t.Run("RecordOverride", func(t *testing.T) {
		s := setupStore(t)
		// First vote.
		_, err := s.Record(ctx, "hash-bob", "ballot-a", votermap.ChannelOnline, time.Unix(1700000000, 0))
		if err != nil {
			t.Fatalf("Record first: %v", err)
		}

		// Override vote.
		prev, err := s.Record(ctx, "hash-bob", "ballot-b", votermap.ChannelInPerson, time.Unix(1700001000, 0))
		if err != nil {
			t.Fatalf("Record override: %v", err)
		}
		if prev != "ballot-a" {
			t.Fatalf("expected prev %q, got %q", "ballot-a", prev)
		}
	})

	t.Run("GetActiveBallotID", func(t *testing.T) {
		s := setupStore(t)
		_, err := s.Record(ctx, "hash-carol", "ballot-c", votermap.ChannelOnline, time.Unix(1700000000, 0))
		if err != nil {
			t.Fatalf("Record: %v", err)
		}

		id, found, err := s.GetActiveBallotID(ctx, "hash-carol")
		if err != nil {
			t.Fatalf("GetActiveBallotID: %v", err)
		}
		if !found {
			t.Fatal("expected found=true")
		}
		if id != "ballot-c" {
			t.Fatalf("expected %q, got %q", "ballot-c", id)
		}

		// Not found case.
		_, found, err = s.GetActiveBallotID(ctx, "hash-unknown")
		if err != nil {
			t.Fatalf("GetActiveBallotID unknown: %v", err)
		}
		if found {
			t.Fatal("expected found=false for unknown voter")
		}
	})

	t.Run("ActiveSet", func(t *testing.T) {
		s := setupStore(t)

		// Record 3 voters; override one.
		s.Record(ctx, "hash-1", "b-1", votermap.ChannelOnline, time.Unix(1700000000, 0))
		s.Record(ctx, "hash-2", "b-2", votermap.ChannelOnline, time.Unix(1700000000, 0))
		s.Record(ctx, "hash-3", "b-3", votermap.ChannelInPerson, time.Unix(1700000000, 0))
		s.Record(ctx, "hash-1", "b-1-new", votermap.ChannelInPerson, time.Unix(1700001000, 0)) // override

		ids, err := s.ActiveSet(ctx)
		if err != nil {
			t.Fatalf("ActiveSet: %v", err)
		}
		if len(ids) != 3 {
			t.Fatalf("expected 3 active ballots, got %d", len(ids))
		}

		// Verify override took effect: b-1-new should be present, b-1 should not.
		found := make(map[string]bool)
		for _, id := range ids {
			found[id] = true
		}
		if found["b-1"] {
			t.Fatal("old ballot b-1 should not be in active set")
		}
		if !found["b-1-new"] {
			t.Fatal("overridden ballot b-1-new should be in active set")
		}
	})

	t.Run("Size", func(t *testing.T) {
		s := setupStore(t)

		s.Record(ctx, "hash-x", "bx", votermap.ChannelOnline, time.Unix(1700000000, 0))
		s.Record(ctx, "hash-y", "by", votermap.ChannelOnline, time.Unix(1700000000, 0))
		s.Record(ctx, "hash-x", "bx2", votermap.ChannelInPerson, time.Unix(1700001000, 0)) // override, not a new voter

		size, err := s.Size(ctx)
		if err != nil {
			t.Fatalf("Size: %v", err)
		}
		if size != 2 {
			t.Fatalf("expected 2 unique voters, got %d", size)
		}
	})

	t.Run("HasVoted", func(t *testing.T) {
		s := setupStore(t)

		s.Record(ctx, "hash-voter", "bv", votermap.ChannelOnline, time.Unix(1700000000, 0))

		voted, err := s.HasVoted(ctx, "hash-voter")
		if err != nil {
			t.Fatalf("HasVoted: %v", err)
		}
		if !voted {
			t.Fatal("expected true for recorded voter")
		}

		voted, err = s.HasVoted(ctx, "hash-nobody")
		if err != nil {
			t.Fatalf("HasVoted unknown: %v", err)
		}
		if voted {
			t.Fatal("expected false for unknown voter")
		}
	})

	t.Run("HistoryRecordNew", func(t *testing.T) {
		s := setupStore(t)
		s.Record(ctx, "hash-alice", "ballot-1", votermap.ChannelOnline, time.Unix(1700000000, 0))

		history, err := s.GetOverrideHistory(ctx, "hash-alice")
		if err != nil {
			t.Fatalf("GetOverrideHistory: %v", err)
		}
		if len(history) != 1 {
			t.Fatalf("expected 1 history entry, got %d", len(history))
		}
		if history[0].Seq != 1 {
			t.Fatalf("expected seq 1, got %d", history[0].Seq)
		}
		if history[0].RowHash == "" {
			t.Fatal("row_hash should not be empty")
		}
	})

	t.Run("HistoryRecordOverride", func(t *testing.T) {
		s := setupStore(t)
		s.Record(ctx, "hash-bob", "ballot-a", votermap.ChannelOnline, time.Unix(1700000000, 0))
		s.Record(ctx, "hash-bob", "ballot-b", votermap.ChannelInPerson, time.Unix(1700001000, 0))

		history, err := s.GetOverrideHistory(ctx, "hash-bob")
		if err != nil {
			t.Fatalf("GetOverrideHistory: %v", err)
		}
		if len(history) != 2 {
			t.Fatalf("expected 2 history entries, got %d", len(history))
		}
		if history[0].Seq != 1 || history[1].Seq != 2 {
			t.Fatalf("expected seq 1,2 got %d,%d", history[0].Seq, history[1].Seq)
		}
		// Verify hash chain
		if history[0].RowHash == history[1].RowHash {
			t.Fatal("different entries should have different row hashes")
		}
	})

	t.Run("GetAllOverrideChains", func(t *testing.T) {
		s := setupStore(t)
		// Voter with override (2 submissions)
		s.Record(ctx, "hash-1", "b-1", votermap.ChannelOnline, time.Unix(1700000000, 0))
		s.Record(ctx, "hash-1", "b-1-new", votermap.ChannelInPerson, time.Unix(1700001000, 0))
		// Voter without override (1 submission)
		s.Record(ctx, "hash-2", "b-2", votermap.ChannelOnline, time.Unix(1700000000, 0))
		// Another voter with override
		s.Record(ctx, "hash-3", "b-3", votermap.ChannelOnline, time.Unix(1700000000, 0))
		s.Record(ctx, "hash-3", "b-3-new", votermap.ChannelOnline, time.Unix(1700002000, 0))

		var chains []votermap.OverrideChain
		err := s.GetAllOverrideChains(ctx, func(c votermap.OverrideChain) error {
			chains = append(chains, c)
			return nil
		})
		if err != nil {
			t.Fatalf("GetAllOverrideChains: %v", err)
		}
		if len(chains) != 2 {
			t.Fatalf("expected 2 override chains (voters with >= 2 submissions), got %d", len(chains))
		}
		// Verify each chain has 2 submissions
		for _, c := range chains {
			if len(c.Submissions) != 2 {
				t.Fatalf("chain for %s: expected 2 submissions, got %d", c.EgnHash, len(c.Submissions))
			}
		}
	})

	t.Run("RowHashChainIntegrity", func(t *testing.T) {
		s := setupStore(t)
		s.Record(ctx, "hash-chain", "b1", votermap.ChannelOnline, time.Unix(1700000000, 0))
		s.Record(ctx, "hash-chain", "b2", votermap.ChannelInPerson, time.Unix(1700001000, 0))
		s.Record(ctx, "hash-chain", "b3", votermap.ChannelOnline, time.Unix(1700002000, 0))

		history, err := s.GetOverrideHistory(ctx, "hash-chain")
		if err != nil {
			t.Fatal(err)
		}
		if len(history) != 3 {
			t.Fatalf("expected 3 entries, got %d", len(history))
		}
		// Verify hash chain: each row's hash should chain from the previous
		prevHash := ""
		for _, entry := range history {
			expected := votermap.ComputeRowHash(testHistoryKey, prevHash, "hash-chain", entry.BallotID, entry.Seq)
			if entry.RowHash != expected {
				t.Fatalf("seq %d: row_hash mismatch: got %s, expected %s", entry.Seq, entry.RowHash, expected)
			}
			prevHash = entry.RowHash
		}
	})
}
