package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/valy0/otvoren-vot/collection/store"
	"github.com/valy0/otvoren-vot/collection/votermap"
)

const testElectionID = "550e8400-e29b-41d4-a716-446655440000"

var testHistoryKey = []byte("test-history-key")

func testDatabaseURL() string {
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		return url
	}
	return "postgres://collection:dev@localhost:5433/collection?sslmode=disable"
}

func setupStore(t *testing.T) *store.PostgresStore {
	t.Helper()
	ctx := context.Background()

	s, err := store.New(ctx, testDatabaseURL(), testElectionID, testHistoryKey)
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	if err := s.RunMigrations(ctx); err != nil {
		t.Fatalf("migrations failed: %v", err)
	}

	// Clean table for test isolation.
	s.Pool().Exec(ctx, "TRUNCATE voters")

	t.Cleanup(func() { s.Close() })
	return s
}

func TestPostgresStore(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()

	t.Run("RecordNew", func(t *testing.T) {
		prev, err := s.Record(ctx, "hash-alice", "ballot-1", votermap.ChannelOnline, time.Unix(1700000000, 0))
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
		if prev != "" {
			t.Fatalf("expected empty prev for new voter, got %q", prev)
		}
	})

	t.Run("RecordOverride", func(t *testing.T) {
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
		// Clean slate.
		s.Pool().Exec(ctx, "TRUNCATE voters")

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
		s.Pool().Exec(ctx, "TRUNCATE voters")

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
		s.Pool().Exec(ctx, "TRUNCATE voters")

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
}
