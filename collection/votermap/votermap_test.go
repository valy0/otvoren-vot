package votermap

import (
	"context"
	"testing"
)

var (
	ctx         = context.Background()
	testHMACKey = []byte("test-hmac-key")
)

func h(egn string) string { return HashEGN(egn, testHMACKey) }

func TestRecordAndRetrieve(t *testing.T) {
	vm := NewMemoryStore()
	prev, err := vm.Record(ctx, h("8501011234"), "ballot-1", "online", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if prev != "" {
		t.Fatal("first vote should have no previous")
	}
	id, ok, err := vm.GetActiveBallotID(ctx, h("8501011234"))
	if err != nil {
		t.Fatal(err)
	}
	if !ok || id != "ballot-1" {
		t.Fatalf("expected ballot-1, got %s", id)
	}
}

func TestOverride(t *testing.T) {
	vm := NewMemoryStore()
	vm.Record(ctx, h("8501011234"), "ballot-1", "online", 1000)
	prev, err := vm.Record(ctx, h("8501011234"), "ballot-2", "in-person", 2000)
	if err != nil {
		t.Fatal(err)
	}
	if prev != "ballot-1" {
		t.Fatalf("expected previous ballot-1, got %s", prev)
	}
	id, _, err := vm.GetActiveBallotID(ctx, h("8501011234"))
	if err != nil {
		t.Fatal(err)
	}
	if id != "ballot-2" {
		t.Fatalf("expected ballot-2 after override, got %s", id)
	}
}

func TestActiveSet(t *testing.T) {
	vm := NewMemoryStore()
	vm.Record(ctx, h("1111111111"), "b1", "online", 1000)
	vm.Record(ctx, h("2222222222"), "b2", "online", 1000)
	vm.Record(ctx, h("3333333333"), "b3", "in-person", 1000)
	// Override voter 1
	vm.Record(ctx, h("1111111111"), "b4", "in-person", 2000)

	set, err := vm.ActiveSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 3 {
		t.Fatalf("expected 3 active ballots, got %d", len(set))
	}
	// b1 should NOT be in the set (overridden by b4)
	for _, id := range set {
		if id == "b1" {
			t.Fatal("b1 should have been overridden")
		}
	}
}

func TestSize(t *testing.T) {
	vm := NewMemoryStore()
	size, err := vm.Size(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if size != 0 {
		t.Fatal("empty map should have size 0")
	}
	vm.Record(ctx, h("1111111111"), "b1", "online", 1000)
	vm.Record(ctx, h("2222222222"), "b2", "online", 1000)
	vm.Record(ctx, h("1111111111"), "b3", "online", 2000) // override, not new voter
	size, err = vm.Size(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if size != 2 {
		t.Fatalf("expected 2 unique voters, got %d", size)
	}
}

func TestHasVoted(t *testing.T) {
	vm := NewMemoryStore()
	voted, err := vm.HasVoted(ctx, h("8501011234"))
	if err != nil {
		t.Fatal(err)
	}
	if voted {
		t.Fatal("should not have voted yet")
	}
	vm.Record(ctx, h("8501011234"), "b1", "online", 1000)
	voted, err = vm.HasVoted(ctx, h("8501011234"))
	if err != nil {
		t.Fatal(err)
	}
	if !voted {
		t.Fatal("should have voted")
	}
}

func TestComputeRowHash(t *testing.T) {
	key := []byte("test-history-key")
	h1 := ComputeRowHash(key, "", "egn1", "ballot1", 1)
	h2 := ComputeRowHash(key, "", "egn1", "ballot1", 1)
	if h1 != h2 {
		t.Fatal("same input should produce same hash")
	}
	if len(h1) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(h1))
	}
	// Chain: second row includes first row's hash
	h3 := ComputeRowHash(key, h1, "egn1", "ballot2", 2)
	if h3 == h1 {
		t.Fatal("different inputs should produce different hashes")
	}
	// Different key produces different hash
	h4 := ComputeRowHash([]byte("other-key"), "", "egn1", "ballot1", 1)
	if h1 == h4 {
		t.Fatal("different keys should produce different hashes")
	}
}

func TestOverrideChainActiveBallotID(t *testing.T) {
	chain := OverrideChain{
		EgnHash: "hash1",
		Submissions: []HistoryEntry{
			{BallotID: "b1", Seq: 1},
			{BallotID: "b2", Seq: 2},
		},
	}
	if chain.ActiveBallotID() != "b2" {
		t.Fatalf("expected b2, got %s", chain.ActiveBallotID())
	}
	empty := OverrideChain{}
	if empty.ActiveBallotID() != "" {
		t.Fatal("empty chain should return empty string")
	}
}

func TestHashEGN(t *testing.T) {
	key := []byte("test-key")
	h1 := HashEGN("8501011234", key)
	h2 := HashEGN("8501011234", key)
	if h1 != h2 {
		t.Fatal("same input should produce same hash")
	}
	if len(h1) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(h1))
	}
	h3 := HashEGN("9912319999", key)
	if h1 == h3 {
		t.Fatal("different inputs should produce different hashes")
	}
	// Different key produces different hash
	h4 := HashEGN("8501011234", []byte("other-key"))
	if h1 == h4 {
		t.Fatal("different keys should produce different hashes")
	}
}
