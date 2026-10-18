package merkle

import (
	"encoding/hex"
	"errors"
	"math"
	"slices"
	"testing"
	"time"
)

// refLeavesHex is the RFC 6962 reference test data.
var refLeavesHex = []string{
	"",
	"00",
	"10",
	"2021",
	"3031",
	"40414243",
	"5051525354555657",
	"606162636465666768696a6b6c6d6e6f",
}

// refRootsHex[n] is the head of the tree of the first n reference leaves.
var refRootsHex = []string{
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

// refInclusion pins audit paths over the reference leaves, nearest sibling
// first (RFC 9162 PATH order).
var refInclusion = []struct {
	index, size uint64
	path        []string
}{
	{0, 8, []string{
		"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
		"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
		"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
	}},
	{5, 8, []string{
		"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
		"ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	}},
	{2, 3, []string{
		"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	}},
}

// refConsistency pins consistency proofs over the reference leaves, in RFC
// 9162 PROOF order: the deepest subtree first.
var refConsistency = []struct {
	size1, size2 uint64
	proof        []string
}{
	{6, 8, []string{
		"0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
		"ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	}},
	{2, 5, []string{
		"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
		"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
	}},
	{4, 8, []string{
		"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
	}},
}

// refLeaves decodes refLeavesHex.
func refLeaves(t testing.TB) [][]byte {
	t.Helper()
	leaves := make([][]byte, len(refLeavesHex))
	for i, s := range refLeavesHex {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("reference leaf %d: %v", i, err)
		}
		leaves[i] = b
	}
	return leaves
}

// mustHash decodes one pinned hex hash.
func mustHash(t testing.TB, s string) Hash {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != HashSize {
		t.Fatalf("bad pinned hash %q", s)
	}
	return Hash(b)
}

// mustHashes decodes a list of pinned hex hashes.
func mustHashes(t testing.TB, ss []string) []Hash {
	t.Helper()
	hs := make([]Hash, len(ss))
	for i, s := range ss {
		hs[i] = mustHash(t, s)
	}
	return hs
}

// refRoot is the pinned head of the tree of the first n reference leaves.
func refRoot(t testing.TB, n int) Hash {
	t.Helper()
	return mustHash(t, refRootsHex[n])
}

// buildTree appends every leaf, in order, to a new tree.
func buildTree(leaves [][]byte) *Tree {
	tree := New()
	for _, d := range leaves {
		tree.Append(d)
	}
	return tree
}

// leaves64 is the data of the 64-leaf cross-check tree: leaf i is
// {byte(i), byte(i >> 8)}.
func leaves64() [][]byte {
	leaves := make([][]byte, 64)
	for i := range leaves {
		leaves[i] = []byte{byte(i), byte(i >> 8)}
	}
	return leaves
}

// sameHashes reports whether got equals the oracle's want, element by element.
func sameHashes(got []Hash, want [][32]byte) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestEmptyTree(t *testing.T) {
	tree := New()
	if got := tree.Size(); got != 0 {
		t.Fatalf("Size() = %d, want 0", got)
	}
	want := refRoot(t, 0)
	if got := EmptyRoot(); got != want {
		t.Fatalf("EmptyRoot() = %x, want %x", got, want)
	}
	if got := tree.Root(); got != want {
		t.Fatalf("Root() = %x, want %x", got, want)
	}
	if got, err := tree.RootAt(0); err != nil || got != want {
		t.Fatalf("RootAt(0) = %x, %v; want %x, nil", got, err, want)
	}
	if _, err := tree.InclusionProof(0, 0); !errors.Is(err, ErrIndexOutOfRange) {
		t.Fatalf("InclusionProof(0, 0) error = %v, want %v", err, ErrIndexOutOfRange)
	}
}

func TestReferenceRoots(t *testing.T) {
	leaves := refLeaves(t)
	tree := New()
	for i, d := range leaves {
		if got := tree.Append(d); got != uint64(i) {
			t.Fatalf("Append #%d returned index %d", i, got)
		}
		if got := tree.Size(); got != uint64(i+1) {
			t.Fatalf("Size() = %d, want %d", got, i+1)
		}
		if got, want := tree.Root(), refRoot(t, i+1); got != want {
			t.Fatalf("Root() after %d leaves = %x, want %x", i+1, got, want)
		}
	}
	for n := range len(leaves) + 1 {
		want := refRoot(t, n)
		if got, err := tree.RootAt(uint64(n)); err != nil || got != want {
			t.Fatalf("RootAt(%d) = %x, %v; want %x, nil", n, got, err, want)
		}
	}
}

func TestReferenceInclusionProofs(t *testing.T) {
	leaves := refLeaves(t)
	tree := buildTree(leaves)
	for _, tc := range refInclusion {
		want := mustHashes(t, tc.path)
		got, err := tree.InclusionProof(tc.index, tc.size)
		if err != nil {
			t.Fatalf("InclusionProof(%d, %d): %v", tc.index, tc.size, err)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("InclusionProof(%d, %d) = %x, want %x", tc.index, tc.size, got, want)
		}
		root := refRoot(t, int(tc.size))
		if err := VerifyInclusion(LeafHash(leaves[tc.index]), tc.index, tc.size, got, root); err != nil {
			t.Fatalf("VerifyInclusion(%d, %d): %v", tc.index, tc.size, err)
		}
	}
}

func TestInclusionMatchesReference(t *testing.T) {
	leaves := leaves64()
	tree := buildTree(leaves)
	for size := 1; size <= len(leaves); size++ {
		root := refMTH(leaves[:size])
		if got, err := tree.RootAt(uint64(size)); err != nil || got != root {
			t.Fatalf("RootAt(%d) = %x, %v; want %x, nil", size, got, err, root)
		}
		for index := range size {
			proof, err := tree.InclusionProof(uint64(index), uint64(size))
			if err != nil {
				t.Fatalf("InclusionProof(%d, %d): %v", index, size, err)
			}
			if want := refPath(index, leaves[:size]); !sameHashes(proof, want) {
				t.Fatalf("InclusionProof(%d, %d) = %x, want %x", index, size, proof, want)
			}
			if err := VerifyInclusion(LeafHash(leaves[index]), uint64(index), uint64(size), proof, root); err != nil {
				t.Fatalf("VerifyInclusion(%d, %d): %v", index, size, err)
			}
		}
	}
}

func TestVerifyInclusionRejects(t *testing.T) {
	leaves := refLeaves(t)
	tree := buildTree(leaves)
	proof := func(index, size uint64) []Hash {
		t.Helper()
		p, err := tree.InclusionProof(index, size)
		if err != nil {
			t.Fatalf("InclusionProof(%d, %d): %v", index, size, err)
		}
		return p
	}
	leaf := func(i int) Hash { return LeafHash(leaves[i]) }
	root := func(n int) Hash { return refRoot(t, n) }

	p23, p58, p12 := proof(2, 3), proof(5, 8), proof(1, 2)
	flipped := slices.Clone(p58)
	flipped[1][0] ^= 0x01

	cases := []struct {
		name        string
		leaf        Hash
		index, size uint64
		proof       []Hash
		root        Hash
		want        error
	}{
		{"index equals size", leaf(5), 8, 8, p58, root(8), ErrIndexOutOfRange},
		{"size zero", leaf(0), 0, 0, nil, root(0), ErrIndexOutOfRange},
		{"(2, 3) proof offered as (3, 3)", leaf(2), 3, 3, p23, root(3), ErrIndexOutOfRange},
		{"(2, 3) proof offered as (0, 1000)", leaf(2), 0, 1000, p23, root(3), ErrInvalidProof},
		{"(5, 8) proof truncated by one", leaf(5), 5, 8, p58[:len(p58)-1], root(8), ErrInvalidProof},
		{"(5, 8) proof with one extra hash", leaf(5), 5, 8, append(slices.Clone(p58), leaf(0)), root(8), ErrInvalidProof},
		// Only the step-4a length rule (sn reaches 0 with proof left) rejects
		// this: the extra hash would otherwise climb to the size-2 root.
		{"(1, 2) proof offered as (0, 1)", leaf(1), 0, 1, p12, root(2), ErrInvalidProof},
		{"wrong leaf", leaf(4), 5, 8, p58, root(8), ErrInvalidProof},
		{"flipped byte in a proof hash", leaf(5), 5, 8, flipped, root(8), ErrInvalidProof},
		{"wrong root", leaf(5), 5, 8, p58, root(7), ErrInvalidProof},
		{"(1, 2) proof offered as (2^32+1, 2^32+2)", leaf(1), 1<<32 + 1, 1<<32 + 2, p12, root(2), ErrInvalidProof},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyInclusion(tc.leaf, tc.index, tc.size, tc.proof, tc.root)
			if !errors.Is(err, tc.want) {
				t.Fatalf("VerifyInclusion error = %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("index 2^63 at size MaxUint64", func(t *testing.T) {
		start := time.Now()
		err := VerifyInclusion(leaf(5), 1<<63, math.MaxUint64, p58, root(8))
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("VerifyInclusion accepted a 3-hash proof at index 2^63, size 2^64-1")
		}
		if budget := 10 * time.Millisecond; elapsed > budget {
			t.Fatalf("VerifyInclusion took %v, budget %v", elapsed, budget)
		}
	})
}

// TestNoDuplicateLastNode is finding L1: an unpaired last node must not be
// duplicated, so [a, b, c] and [a, b, c, c] are different trees.
func TestNoDuplicateLastNode(t *testing.T) {
	a, b, c := []byte("a"), []byte("b"), []byte("c")
	t3 := buildTree([][]byte{a, b, c})
	t4 := buildTree([][]byte{a, b, c, c})
	if t3.Root() == t4.Root() {
		t.Fatalf("[a, b, c] and [a, b, c, c] share the root %x", t3.Root())
	}
	p, err := t4.InclusionProof(3, 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []uint64{3, 2} {
		if err := VerifyInclusion(LeafHash(c), index, 3, p, t3.Root()); err == nil {
			t.Fatalf("the 4-leaf proof for index 3 verified as index %d at size 3", index)
		}
	}
}

func TestProofRequestsOutOfRange(t *testing.T) {
	tree := buildTree(refLeaves(t))
	n := tree.Size()
	cases := []struct {
		name string
		call func() error
		want error
	}{
		{"InclusionProof(0, Size()+1)", func() error { _, err := tree.InclusionProof(0, n+1); return err }, ErrSizeOutOfRange},
		{"InclusionProof(Size(), Size())", func() error { _, err := tree.InclusionProof(n, n); return err }, ErrIndexOutOfRange},
		{"RootAt(Size()+1)", func() error { _, err := tree.RootAt(n + 1); return err }, ErrSizeOutOfRange},
		{"InclusionProof(MaxUint64, MaxUint64)", func() error { _, err := tree.InclusionProof(math.MaxUint64, math.MaxUint64); return err }, ErrSizeOutOfRange},
		{"RootAt(MaxUint64)", func() error { _, err := tree.RootAt(math.MaxUint64); return err }, ErrSizeOutOfRange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestReferenceConsistencyProofs(t *testing.T) {
	tree := buildTree(refLeaves(t))
	for _, tc := range refConsistency {
		want := mustHashes(t, tc.proof)
		got, err := tree.ConsistencyProof(tc.size1, tc.size2)
		if err != nil {
			t.Fatalf("ConsistencyProof(%d, %d): %v", tc.size1, tc.size2, err)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("ConsistencyProof(%d, %d) = %x, want %x", tc.size1, tc.size2, got, want)
		}
		root1, root2 := refRoot(t, int(tc.size1)), refRoot(t, int(tc.size2))
		if err := VerifyConsistency(tc.size1, tc.size2, root1, root2, got); err != nil {
			t.Fatalf("VerifyConsistency(%d, %d): %v", tc.size1, tc.size2, err)
		}
	}
}

func TestConsistencyMatchesReference(t *testing.T) {
	leaves := leaves64()
	tree := buildTree(leaves)
	roots := make([][32]byte, len(leaves)+1)
	for n := range roots {
		roots[n] = refMTH(leaves[:n])
	}
	for n := 2; n <= len(leaves); n++ {
		for m := 1; m < n; m++ {
			proof, err := tree.ConsistencyProof(uint64(m), uint64(n))
			if err != nil {
				t.Fatalf("ConsistencyProof(%d, %d): %v", m, n, err)
			}
			if want := refSubproof(m, leaves[:n], true); !sameHashes(proof, want) {
				t.Fatalf("ConsistencyProof(%d, %d) = %x, want %x", m, n, proof, want)
			}
			if err := VerifyConsistency(uint64(m), uint64(n), roots[m], roots[n], proof); err != nil {
				t.Fatalf("VerifyConsistency(%d, %d): %v", m, n, err)
			}
		}
	}
}

// TestConsistencyEdgeSizes covers the conventions of merkle.md §4 that lie
// outside the RFC's 0 < size1 < size2: there is nothing to prove, so the
// proof is empty.
func TestConsistencyEdgeSizes(t *testing.T) {
	tree := buildTree(refLeaves(t))
	empty := EmptyRoot()
	for n := range tree.Size() + 1 {
		root := refRoot(t, int(n))
		for _, tc := range []struct {
			size1 uint64
			root1 Hash
		}{{0, empty}, {n, root}} {
			proof, err := tree.ConsistencyProof(tc.size1, n)
			if err != nil {
				t.Fatalf("ConsistencyProof(%d, %d): %v", tc.size1, n, err)
			}
			if len(proof) != 0 {
				t.Fatalf("ConsistencyProof(%d, %d) = %x, want an empty proof", tc.size1, n, proof)
			}
			if err := VerifyConsistency(tc.size1, n, tc.root1, root, proof); err != nil {
				t.Fatalf("VerifyConsistency(%d, %d): %v", tc.size1, n, err)
			}
		}
	}

	proof, err := New().ConsistencyProof(0, 0)
	if err != nil || len(proof) != 0 {
		t.Fatalf("empty tree: ConsistencyProof(0, 0) = %x, %v; want an empty proof", proof, err)
	}
	if err := VerifyConsistency(0, 0, empty, empty, nil); err != nil {
		t.Fatalf("VerifyConsistency(0, 0) with empty roots: %v", err)
	}
}

func TestVerifyConsistencyRejects(t *testing.T) {
	leaves := refLeaves(t)
	tree := buildTree(leaves)
	proof := func(size1, size2 uint64) []Hash {
		t.Helper()
		p, err := tree.ConsistencyProof(size1, size2)
		if err != nil {
			t.Fatalf("ConsistencyProof(%d, %d): %v", size1, size2, err)
		}
		return p
	}
	root := func(n int) Hash { return refRoot(t, n) }

	// rewritten is the reference tree with leaf 1 changed: a history the
	// board rewrote.
	rewrittenLeaves := slices.Clone(leaves)
	rewrittenLeaves[1] = []byte{0x01}
	rewritten := buildTree(rewrittenLeaves)
	rewrittenRoot := func(n uint64) Hash {
		t.Helper()
		r, err := rewritten.RootAt(n)
		if err != nil {
			t.Fatalf("rewritten RootAt(%d): %v", n, err)
		}
		return r
	}

	p68, p78, p12 := proof(6, 8), proof(7, 8), proof(1, 2)

	cases := []struct {
		name         string
		size1, size2 uint64
		root1, root2 Hash
		proof        []Hash
		want         error
	}{
		{"size1 > size2", 8, 6, root(8), root(6), p68, ErrSizeOutOfRange},
		// Only the size1 > size2 rule rejects this: the RFC walk alone
		// accepts it (fn = 2, sn = 0, and the one hash is both heads).
		{"(3 → 1) that the RFC walk alone accepts", 3, 1, root(1), root(1), []Hash{root(1)}, ErrSizeOutOfRange},
		{"size1 == size2 with a non-empty proof", 8, 8, root(8), root(8), []Hash{root(8)}, ErrInvalidProof},
		{"size1 == size2 with different roots", 8, 8, root(8), root(7), nil, ErrInvalidProof},
		{"(0 → 0) with root2 ≠ EmptyRoot()", 0, 0, root(0), root(1), nil, ErrInvalidProof},
		{"size1 == 0 with a non-empty proof", 0, 8, root(0), root(8), []Hash{root(8)}, ErrInvalidProof},
		{"size1 == 0 with root1 ≠ EmptyRoot()", 0, 8, root(1), root(8), nil, ErrInvalidProof},
		// Only step 1 (empty proof) rejects this; without it there is no
		// first proof hash to start the walk from.
		{"(6 → 8) with an empty proof", 6, 8, root(6), root(8), nil, ErrInvalidProof},
		{"(6 → 8) proof truncated by one", 6, 8, root(6), root(8), p68[:len(p68)-1], ErrInvalidProof},
		{"(6 → 8) proof with one extra hash", 6, 8, root(6), root(8), append(slices.Clone(p68), LeafHash(leaves[0])), ErrInvalidProof},
		{"roots swapped", 6, 8, root(8), root(6), p68, ErrInvalidProof},
		{"root1 from a tree whose leaf 1 was changed", 6, 8, rewrittenRoot(6), root(8), p68, ErrInvalidProof},
		// Only the final sr == root2 check rejects this.
		{"root2 from a tree whose leaf 1 was changed", 6, 8, root(6), rewrittenRoot(8), p68, ErrInvalidProof},
		// Only the step-6a rule (sn reaches 0 with proof left) rejects this:
		// the last hash would otherwise climb both heads to sizes 7 and 8.
		{"(7 → 8) proof offered as (3 → 4)", 3, 4, root(7), root(8), p78, ErrInvalidProof},
		// Only the final sn == 0 check rejects this: the walk ends on the
		// heads of sizes 6 and 8 with sn = 1.
		{"(6 → 8) proof offered as (6 → 9)", 6, 9, root(6), root(8), p68, ErrInvalidProof},
		{"(1 → 2) proof offered as (2^32+1 → 2^32+2)", 1<<32 + 1, 1<<32 + 2, root(1), root(2), p12, ErrInvalidProof},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyConsistency(tc.size1, tc.size2, tc.root1, tc.root2, tc.proof)
			if !errors.Is(err, tc.want) {
				t.Fatalf("VerifyConsistency error = %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("size1 2^63 to size2 MaxUint64", func(t *testing.T) {
		start := time.Now()
		err := VerifyConsistency(1<<63, math.MaxUint64, root(6), root(8), p68)
		elapsed := time.Since(start)
		if !errors.Is(err, ErrInvalidProof) {
			t.Fatalf("VerifyConsistency error = %v, want %v", err, ErrInvalidProof)
		}
		if budget := 10 * time.Millisecond; elapsed > budget {
			t.Fatalf("VerifyConsistency took %v, budget %v", elapsed, budget)
		}
	})
}

func TestConsistencyRequestsOutOfRange(t *testing.T) {
	tree := buildTree(refLeaves(t))
	n := tree.Size()
	cases := []struct {
		name         string
		size1, size2 uint64
	}{
		{"ConsistencyProof(1, Size()+1)", 1, n + 1},
		{"ConsistencyProof(3, 2)", 3, 2},
		{"ConsistencyProof(Size(), Size()-1)", n, n - 1},
		{"ConsistencyProof(0, MaxUint64)", 0, math.MaxUint64},
		{"ConsistencyProof(MaxUint64, MaxUint64)", math.MaxUint64, math.MaxUint64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tree.ConsistencyProof(tc.size1, tc.size2); !errors.Is(err, ErrSizeOutOfRange) {
				t.Fatalf("error = %v, want %v", err, ErrSizeOutOfRange)
			}
		})
	}
}

func TestAppendDoesNotRetainData(t *testing.T) {
	data := []byte("ballot")
	tree := New()
	tree.Append(data)
	want := tree.Root()
	data[0] ^= 0xff
	if got := tree.Root(); got != want {
		t.Fatalf("Root() changed from %x to %x after the appended slice was mutated", want, got)
	}
}

// TestLargeTree appends 10 000 leaves within a time budget, then checks an
// inclusion proof for every leaf against the root.
func TestLargeTree(t *testing.T) {
	const n = 10_000
	leaf := func(i uint64) []byte { return []byte{byte(i >> 8), byte(i)} }
	tree := New()

	start := time.Now()
	for i := range uint64(n) {
		tree.Append(leaf(i))
	}
	root := tree.Root()
	elapsed := time.Since(start)

	if tree.Size() != n {
		t.Fatalf("Size() = %d, want %d", tree.Size(), n)
	}
	if root == EmptyRoot() {
		t.Fatal("Root() of a 10 000-leaf tree is the empty root")
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

	for i := range uint64(n) {
		p, err := tree.InclusionProof(i, n)
		if err != nil {
			t.Fatalf("InclusionProof(%d, %d): %v", i, n, err)
		}
		if err := VerifyInclusion(LeafHash(leaf(i)), i, n, p, root); err != nil {
			t.Fatalf("VerifyInclusion(%d, %d): %v", i, n, err)
		}
	}
}
