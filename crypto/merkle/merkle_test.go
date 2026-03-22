package merkle

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestEmptyTree(t *testing.T) {
	tree := New()
	if tree.Root() != nil {
		t.Fatal("empty tree should have nil root")
	}
	if tree.Size() != 0 {
		t.Fatal("empty tree should have size 0")
	}
}

func TestSingleLeaf(t *testing.T) {
	tree := New()
	tree.Append([]byte("only"))
	if tree.Root() == nil {
		t.Fatal("single-leaf tree should have a root")
	}
	proof, err := tree.InclusionProof(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) != 0 {
		t.Fatal("single-leaf proof should be empty")
	}
	if !VerifyInclusion(tree.Root(), []byte("only"), 0, 1, proof) {
		t.Fatal("single-leaf inclusion should verify")
	}
}

func TestAppendChangesRoot(t *testing.T) {
	tree := New()
	tree.Append([]byte("a"))
	root1 := make([]byte, len(tree.Root()))
	copy(root1, tree.Root())
	tree.Append([]byte("b"))
	if bytes.Equal(root1, tree.Root()) {
		t.Fatal("root should change after append")
	}
}

func TestInclusionProof(t *testing.T) {
	tree := New()
	for i := range 10 {
		tree.Append([]byte{byte(i)})
	}
	for i := range 10 {
		proof, err := tree.InclusionProof(i)
		if err != nil {
			t.Fatalf("index %d: %v", i, err)
		}
		if !VerifyInclusion(tree.Root(), []byte{byte(i)}, i, tree.Size(), proof) {
			t.Fatalf("index %d should verify", i)
		}
	}
}

func TestInclusionProofTampered(t *testing.T) {
	tree := New()
	tree.Append([]byte("real"))
	proof, _ := tree.InclusionProof(0)
	if VerifyInclusion(tree.Root(), []byte("fake"), 0, tree.Size(), proof) {
		t.Fatal("tampered data should not verify")
	}
}

func TestVerifyEmptyTree(t *testing.T) {
	if VerifyInclusion(nil, []byte("x"), 0, 0, nil) {
		t.Fatal("empty tree verification should fail")
	}
}

func TestOddNumberOfLeaves(t *testing.T) {
	tree := New()
	for i := range 7 {
		tree.Append([]byte{byte(i)})
	}
	for i := range 7 {
		proof, err := tree.InclusionProof(i)
		if err != nil {
			t.Fatalf("index %d: %v", i, err)
		}
		if !VerifyInclusion(tree.Root(), []byte{byte(i)}, i, tree.Size(), proof) {
			t.Fatalf("index %d should verify (odd tree)", i)
		}
	}
}

func TestOutOfRangeIndex(t *testing.T) {
	tree := New()
	tree.Append([]byte("a"))
	_, err := tree.InclusionProof(5)
	if err == nil {
		t.Fatal("out-of-range index should return error")
	}
}

// TestIncrementalRootMatchesFull appends 100 random leaves one at a time and
// verifies that the incremental root matches a full rebuild at every step.
func TestIncrementalRootMatchesFull(t *testing.T) {
	tree := New()
	var allLeaves [][]byte

	for i := range 100 {
		leaf := make([]byte, 32)
		if _, err := rand.Read(leaf); err != nil {
			t.Fatal(err)
		}
		allLeaves = append(allLeaves, leaf)
		tree.Append(leaf)

		// Compute the expected root via the original full-rebuild algorithm.
		hashes := make([][]byte, len(allLeaves))
		for j, l := range allLeaves {
			hashes[j] = hashLeaf(l)
		}
		want := computeRoot(hashes)

		got := tree.Root()
		if !bytes.Equal(got, want) {
			t.Fatalf("root mismatch at %d leaves", i+1)
		}
	}
}

// TestLargeTree appends 10 000 leaves and asserts that the root is computed
// well within a reasonable time budget.
func TestLargeTree(t *testing.T) {
	const n = 10_000
	tree := New()

	start := time.Now()
	for i := range n {
		tree.Append([]byte{byte(i >> 8), byte(i)})
	}
	root := tree.Root()
	elapsed := time.Since(start)

	if root == nil {
		t.Fatal("expected non-nil root")
	}
	if tree.Size() != n {
		t.Fatalf("expected size %d, got %d", n, tree.Size())
	}

	// The race detector adds ~5-10x overhead; only enforce the tight
	// budget in normal builds.
	if !raceEnabled {
		const budget = 100 * time.Millisecond
		if elapsed > budget {
			t.Fatalf("too slow: %v (budget %v)", elapsed, budget)
		}
	}
	t.Logf("10 000 leaves: %v", elapsed)
}
