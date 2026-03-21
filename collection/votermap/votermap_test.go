package votermap

import "testing"

func TestRecordAndRetrieve(t *testing.T) {
	vm := New()
	prev := vm.Record("8501011234", "ballot-1", "online", 1000)
	if prev != "" {
		t.Fatal("first vote should have no previous")
	}
	id, ok := vm.GetActiveBallotID("8501011234")
	if !ok || id != "ballot-1" {
		t.Fatalf("expected ballot-1, got %s", id)
	}
}

func TestOverride(t *testing.T) {
	vm := New()
	vm.Record("8501011234", "ballot-1", "online", 1000)
	prev := vm.Record("8501011234", "ballot-2", "in-person", 2000)
	if prev != "ballot-1" {
		t.Fatalf("expected previous ballot-1, got %s", prev)
	}
	id, _ := vm.GetActiveBallotID("8501011234")
	if id != "ballot-2" {
		t.Fatalf("expected ballot-2 after override, got %s", id)
	}
}

func TestActiveSet(t *testing.T) {
	vm := New()
	vm.Record("1111111111", "b1", "online", 1000)
	vm.Record("2222222222", "b2", "online", 1000)
	vm.Record("3333333333", "b3", "in-person", 1000)
	// Override voter 1
	vm.Record("1111111111", "b4", "in-person", 2000)

	set := vm.ActiveSet()
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
	vm := New()
	if vm.Size() != 0 {
		t.Fatal("empty map should have size 0")
	}
	vm.Record("1111111111", "b1", "online", 1000)
	vm.Record("2222222222", "b2", "online", 1000)
	vm.Record("1111111111", "b3", "online", 2000) // override, not new voter
	if vm.Size() != 2 {
		t.Fatalf("expected 2 unique voters, got %d", vm.Size())
	}
}

func TestHasVoted(t *testing.T) {
	vm := New()
	if vm.HasVoted("8501011234") {
		t.Fatal("should not have voted yet")
	}
	vm.Record("8501011234", "b1", "online", 1000)
	if !vm.HasVoted("8501011234") {
		t.Fatal("should have voted")
	}
}
