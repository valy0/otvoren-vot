package vectors

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/valy0/otvoren-vot/crypto/merkle"
)

// maxJSSafeInt is 2^53 - 1: the largest integer JavaScript's JSON.parse reads
// without rounding. No size or index in merkle.json may exceed it.
const maxJSSafeInt = 1<<53 - 1

const merkleVectorsPath = "testdata/merkle.json"

// MerkleVectors is the schema of testdata/merkle.json, read by the Go tests
// here and by the TypeScript verifier. Every hash is lowercase hex. Empty
// hash lists are [], never null.
type MerkleVectors struct {
	LeavesHex          []string                   `json:"leaves_hex"`
	Roots              []MerkleRoot               `json:"roots"`
	Inclusion          []MerkleInclusion          `json:"inclusion"`
	Consistency        []MerkleConsistency        `json:"consistency"`
	InvalidInclusion   []InvalidMerkleInclusion   `json:"invalid_inclusion"`
	InvalidConsistency []InvalidMerkleConsistency `json:"invalid_consistency"`
}

type MerkleRoot struct {
	Size    uint64 `json:"size"`
	RootHex string `json:"root_hex"`
}

type MerkleInclusion struct {
	Index       uint64   `json:"index"`
	Size        uint64   `json:"size"`
	LeafHashHex string   `json:"leaf_hash_hex"`
	ProofHex    []string `json:"proof_hex"`
	RootHex     string   `json:"root_hex"`
}

type MerkleConsistency struct {
	Size1    uint64   `json:"size1"`
	Size2    uint64   `json:"size2"`
	Root1Hex string   `json:"root1_hex"`
	Root2Hex string   `json:"root2_hex"`
	ProofHex []string `json:"proof_hex"`
}

type InvalidMerkleInclusion struct {
	Case        string   `json:"case"`
	Index       uint64   `json:"index"`
	Size        uint64   `json:"size"`
	LeafHashHex string   `json:"leaf_hash_hex"`
	ProofHex    []string `json:"proof_hex"`
	RootHex     string   `json:"root_hex"`
}

type InvalidMerkleConsistency struct {
	Case     string   `json:"case"`
	Size1    uint64   `json:"size1"`
	Size2    uint64   `json:"size2"`
	Root1Hex string   `json:"root1_hex"`
	Root2Hex string   `json:"root2_hex"`
	ProofHex []string `json:"proof_hex"`
}

// merkleLeavesHex: the 8 RFC 9162 reference leaves, then three more.
var merkleLeavesHex = []string{
	"", "00", "10", "2021", "3031", "40414243",
	"5051525354555657", "606162636465666768696a6b6c6d6e6f",
	"70", "7171", "727272",
}

var requiredInvalidInclusion = []string{
	"index_equals_size", "size_zero", "relabelled_index", "truncated_proof",
	"extra_hash", "wrong_leaf", "wrong_root", "flipped_proof_byte",
	"index_past_u32", "overlong_proof",
}

var requiredInvalidConsistency = []string{
	"size1_greater", "equal_sizes_nonempty_proof", "equal_sizes_different_roots",
	"zero_size1_nonempty_proof", "truncated_proof", "extra_hash", "swapped_roots",
	"rewritten_history", "sizes_past_u32", "zero_size1_root1_not_empty",
	"empty_proof", "rewritten_root2", "relabelled_down", "relabelled_up",
	"zero_sizes_root2_not_empty", "zero_sizes_equal_nonempty_roots",
	"equal_sizes_walk_accepts",
}

func hx(h merkle.Hash) string { return hex.EncodeToString(h[:]) }

// hxs encodes hashes as a non-nil slice, so an empty proof marshals as [].
func hxs(hs []merkle.Hash) []string {
	out := make([]string, 0, len(hs))
	for _, h := range hs {
		out = append(out, hx(h))
	}
	return out
}

func buildMerkleVectors(t testing.TB) MerkleVectors {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	leaves := make([][]byte, len(merkleLeavesHex))
	for i, s := range merkleLeavesHex {
		b, err := hex.DecodeString(s)
		must(err)
		leaves[i] = b
	}
	tree := merkle.New()
	for _, l := range leaves {
		tree.Append(l)
	}
	root := func(n uint64) merkle.Hash {
		t.Helper()
		r, err := tree.RootAt(n)
		must(err)
		return r
	}
	incl := func(i, n uint64) []merkle.Hash {
		t.Helper()
		p, err := tree.InclusionProof(i, n)
		must(err)
		return p
	}
	cons := func(a, b uint64) []merkle.Hash {
		t.Helper()
		p, err := tree.ConsistencyProof(a, b)
		must(err)
		return p
	}
	leaf := func(i int) merkle.Hash { return merkle.LeafHash(leaves[i]) }

	rewrittenLeaves := slices.Clone(leaves)
	rewrittenLeaves[1] = []byte{0x01}
	rewritten := merkle.New()
	for _, l := range rewrittenLeaves {
		rewritten.Append(l)
	}
	rewrittenRoot := func(n uint64) merkle.Hash {
		t.Helper()
		r, err := rewritten.RootAt(n)
		must(err)
		return r
	}

	v := MerkleVectors{LeavesHex: slices.Clone(merkleLeavesHex)}
	n := uint64(len(leaves))

	for size := uint64(0); size <= n; size++ {
		v.Roots = append(v.Roots, MerkleRoot{Size: size, RootHex: hx(root(size))})
	}
	for size := uint64(1); size <= n; size++ {
		for i := uint64(0); i < size; i++ {
			v.Inclusion = append(v.Inclusion, MerkleInclusion{
				Index: i, Size: size, LeafHashHex: hx(leaf(int(i))),
				ProofHex: hxs(incl(i, size)), RootHex: hx(root(size)),
			})
		}
	}
	addCons := func(a, b uint64) {
		v.Consistency = append(v.Consistency, MerkleConsistency{
			Size1: a, Size2: b, Root1Hex: hx(root(a)), Root2Hex: hx(root(b)),
			ProofHex: hxs(cons(a, b)),
		})
	}
	for a := uint64(1); a < n; a++ {
		for b := a + 1; b <= n; b++ {
			addCons(a, b)
		}
	}
	addCons(0, 5)
	addCons(5, 5)

	// Invalid inclusion.
	p23, p58, p12 := incl(2, 3), incl(5, 8), incl(1, 2)
	flipped := slices.Clone(p58)
	flipped[1][0] ^= 0x01
	ii := func(name string, l merkle.Hash, idx, size uint64, p []merkle.Hash, r merkle.Hash) {
		v.InvalidInclusion = append(v.InvalidInclusion, InvalidMerkleInclusion{
			Case: name, Index: idx, Size: size, LeafHashHex: hx(l),
			ProofHex: hxs(p), RootHex: hx(r),
		})
	}
	// Built from the (0, 8) entry: without the index >= size rule the walk
	// treats index 8 like index 0 and reaches root(8).
	ii("index_equals_size", leaf(0), 8, 8, incl(0, 8), root(8))
	ii("size_zero", leaf(0), 0, 0, nil, root(0))
	ii("relabelled_index", leaf(2), 0, 1000, p23, root(3))
	ii("truncated_proof", leaf(5), 5, 8, p58[:len(p58)-1], root(8))
	ii("extra_hash", leaf(5), 5, 8, append(slices.Clone(p58), leaf(0)), root(8))
	ii("wrong_leaf", leaf(4), 5, 8, p58, root(8))
	ii("wrong_root", leaf(5), 5, 8, p58, root(7))
	ii("flipped_proof_byte", leaf(5), 5, 8, flipped, root(8))
	ii("index_past_u32", leaf(1), 1<<32+1, 1<<32+2, p12, root(2))
	ii("overlong_proof", leaf(1), 0, 1, p12, root(2))

	// Invalid consistency.
	p68, p78, p12c := cons(6, 8), cons(7, 8), cons(1, 2)
	ic := func(name string, a, b uint64, r1, r2 merkle.Hash, p []merkle.Hash) {
		v.InvalidConsistency = append(v.InvalidConsistency, InvalidMerkleConsistency{
			Case: name, Size1: a, Size2: b, Root1Hex: hx(r1), Root2Hex: hx(r2),
			ProofHex: hxs(p),
		})
	}
	ic("size1_greater", 3, 1, root(1), root(1), []merkle.Hash{root(1)})
	ic("equal_sizes_nonempty_proof", 8, 8, root(8), root(8), []merkle.Hash{root(8)})
	ic("equal_sizes_different_roots", 8, 8, root(8), root(7), nil)
	ic("zero_size1_nonempty_proof", 0, 8, root(0), root(8), []merkle.Hash{root(8)})
	ic("zero_size1_root1_not_empty", 0, 8, root(1), root(8), nil)
	ic("truncated_proof", 6, 8, root(6), root(8), p68[:len(p68)-1])
	ic("extra_hash", 6, 8, root(6), root(8), append(slices.Clone(p68), leaf(0)))
	ic("empty_proof", 6, 8, root(6), root(8), nil)
	ic("swapped_roots", 6, 8, root(8), root(6), p68)
	ic("rewritten_history", 6, 8, rewrittenRoot(6), root(8), p68)
	ic("rewritten_root2", 6, 8, root(6), rewrittenRoot(8), p68)
	ic("relabelled_down", 3, 4, root(7), root(8), p78)
	ic("relabelled_up", 6, 9, root(6), root(8), p68)
	ic("sizes_past_u32", 1<<32+1, 1<<32+2, root(1), root(2), p12c)
	ic("zero_sizes_root2_not_empty", 0, 0, merkle.EmptyRoot(), root(1), nil)
	ic("zero_sizes_equal_nonempty_roots", 0, 0, root(1), root(1), nil)
	d45 := merkle.NodeHash(leaf(4), leaf(5))
	ic("equal_sizes_walk_accepts", 6, 6, root(6), root(6), []merkle.Hash{d45, root(4)})

	return v
}

func marshalMerkleVectors(t testing.TB) []byte {
	t.Helper()
	data, err := json.MarshalIndent(buildMerkleVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

// TestGenerateMerkleVectors writes testdata/merkle.json.
// Run: go test ./vectors/ -run TestGenerateMerkleVectors -update
func TestGenerateMerkleVectors(t *testing.T) {
	if !*update {
		t.Skip("run with -update to regenerate")
	}
	data := marshalMerkleVectors(t)
	if err := os.WriteFile(merkleVectorsPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d bytes to %s", len(data), merkleVectorsPath)
}

func TestMerkleVectorsUpToDate(t *testing.T) {
	have, err := os.ReadFile(merkleVectorsPath)
	if err != nil {
		t.Fatalf("%s not found; run: go test ./vectors/ -run TestGenerateMerkleVectors -update", merkleVectorsPath)
	}
	if !bytes.Equal(have, marshalMerkleVectors(t)) {
		t.Fatalf("%s is stale; regenerate with: cd crypto && go test ./vectors/ -run TestGenerateMerkleVectors -update", merkleVectorsPath)
	}
}

func decodeHash(t *testing.T, s string) merkle.Hash {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != merkle.HashSize || s != hex.EncodeToString(b) {
		t.Fatalf("bad lowercase hash hex %q", s)
	}
	return merkle.Hash(b)
}

func decodeHashes(t *testing.T, ss []string) []merkle.Hash {
	t.Helper()
	if ss == nil {
		t.Fatal("proof_hex is null, want []")
	}
	out := make([]merkle.Hash, len(ss))
	for i, s := range ss {
		out[i] = decodeHash(t, s)
	}
	return out
}

func TestVerifyMerkleVectors(t *testing.T) {
	data, err := os.ReadFile(merkleVectorsPath)
	if err != nil {
		t.Fatalf("%s not found; run: go test ./vectors/ -run TestGenerateMerkleVectors -update", merkleVectorsPath)
	}
	var v MerkleVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if v.LeavesHex == nil {
		t.Fatal("leaves_hex is null, want a list")
	}
	if len(v.LeavesHex) == 0 || len(v.Roots) == 0 || len(v.Inclusion) == 0 ||
		len(v.Consistency) == 0 || len(v.InvalidInclusion) == 0 || len(v.InvalidConsistency) == 0 {
		t.Fatal("a category of merkle.json is empty")
	}

	tree := merkle.New()
	for _, s := range v.LeavesHex {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		tree.Append(b)
	}
	small := func(label string, ns ...uint64) {
		t.Helper()
		for _, n := range ns {
			if n > maxJSSafeInt {
				t.Fatalf("%s: %d exceeds 2^53-1", label, n)
			}
		}
	}

	for _, r := range v.Roots {
		small("root", r.Size)
		got, err := tree.RootAt(r.Size)
		if err != nil || hx(got) != r.RootHex {
			t.Errorf("root at %d: got %x (%v), file %s", r.Size, got, err, r.RootHex)
		}
	}
	for _, e := range v.Inclusion {
		small("inclusion", e.Index, e.Size)
		if err := merkle.VerifyInclusion(decodeHash(t, e.LeafHashHex), e.Index, e.Size,
			decodeHashes(t, e.ProofHex), decodeHash(t, e.RootHex)); err != nil {
			t.Errorf("inclusion (%d, %d): %v", e.Index, e.Size, err)
		}
		if got, err := tree.RootAt(e.Size); err != nil || hx(got) != e.RootHex {
			t.Errorf("inclusion (%d, %d): root does not match the tree", e.Index, e.Size)
		}
	}
	for _, e := range v.Consistency {
		small("consistency", e.Size1, e.Size2)
		if err := merkle.VerifyConsistency(e.Size1, e.Size2, decodeHash(t, e.Root1Hex),
			decodeHash(t, e.Root2Hex), decodeHashes(t, e.ProofHex)); err != nil {
			t.Errorf("consistency (%d, %d): %v", e.Size1, e.Size2, err)
		}
		for _, c := range []struct {
			size uint64
			hex  string
		}{{e.Size1, e.Root1Hex}, {e.Size2, e.Root2Hex}} {
			if got, err := tree.RootAt(c.size); err != nil || hx(got) != c.hex {
				t.Errorf("consistency (%d, %d): root at %d does not match the tree", e.Size1, e.Size2, c.size)
			}
		}
	}

	seenI := map[string]bool{}
	for _, e := range v.InvalidInclusion {
		small(e.Case, e.Index, e.Size)
		if seenI[e.Case] {
			t.Errorf("duplicate invalid_inclusion case %q", e.Case)
		}
		seenI[e.Case] = true
		if err := merkle.VerifyInclusion(decodeHash(t, e.LeafHashHex), e.Index, e.Size,
			decodeHashes(t, e.ProofHex), decodeHash(t, e.RootHex)); err == nil {
			t.Errorf("invalid_inclusion %q verified", e.Case)
		}
	}
	for _, name := range requiredInvalidInclusion {
		if !seenI[name] {
			t.Errorf("invalid_inclusion case %q missing", name)
		}
	}
	seenC := map[string]bool{}
	for _, e := range v.InvalidConsistency {
		small(e.Case, e.Size1, e.Size2)
		if seenC[e.Case] {
			t.Errorf("duplicate invalid_consistency case %q", e.Case)
		}
		seenC[e.Case] = true
		if err := merkle.VerifyConsistency(e.Size1, e.Size2, decodeHash(t, e.Root1Hex),
			decodeHash(t, e.Root2Hex), decodeHashes(t, e.ProofHex)); err == nil {
			t.Errorf("invalid_consistency %q verified", e.Case)
		}
	}
	for _, name := range requiredInvalidConsistency {
		if !seenC[name] {
			t.Errorf("invalid_consistency case %q missing", name)
		}
	}
}
