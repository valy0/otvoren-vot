package merkle

import "math/bits"

// Tree is an append-only RFC 9162 §2.1 Merkle tree over SHA-256.
//
// It stores hashes only, never leaf data: every complete subtree of 2^L
// leaves aligned on a multiple of 2^L is kept, once, in levels. Append
// costs O(log n) hashes; Root, RootAt, InclusionProof and ConsistencyProof
// rebuild the incomplete right edge from the stored subtrees in O(log n)
// hashes.
//
// A Tree is not safe for concurrent use. Callers that share one must
// serialise access to it.
type Tree struct {
	// levels[L][i] is the hash of the complete subtree of 2^L leaves that
	// starts at leaf i·2^L. len(levels[L]) == Size() >> L, so levels[0]
	// holds the leaf hashes.
	levels [][]Hash
}

// New returns an empty tree, whose head is EmptyRoot() (RFC 9162 §2.1.1).
func New() *Tree {
	return &Tree{}
}

// Append adds the leaf d(n) = data at index n = Size() and returns n. It
// keeps only LeafHash(data) (RFC 9162 §2.1.1), so the caller may reuse data.
func (t *Tree) Append(data []byte) uint64 {
	index := t.Size()
	h, i := LeafHash(data), index
	for level := 0; ; level++ {
		if level == len(t.levels) {
			t.levels = append(t.levels, nil)
		}
		t.levels[level] = append(t.levels[level], h)
		if i&1 == 0 {
			// A left child: its parent is not complete yet.
			break
		}
		// A right child completes its parent at the next level up.
		h = NodeHash(t.levels[level][i-1], h)
		i >>= 1
	}
	return index
}

// Size returns the number of leaves, n (RFC 9162 §2.1.1).
func (t *Tree) Size() uint64 {
	if len(t.levels) == 0 {
		return 0
	}
	return uint64(len(t.levels[0]))
}

// Root returns the tree head MTH(D[n]) for n = Size() (RFC 9162 §2.1.1). It
// is EmptyRoot() when the tree is empty.
func (t *Tree) Root() Hash {
	return t.hashRange(0, t.Size())
}

// RootAt returns the head MTH(D[0:size]) of the tree as it stood when it had
// size leaves (RFC 9162 §2.1.1). It returns ErrSizeOutOfRange if size >
// Size().
func (t *Tree) RootAt(size uint64) (Hash, error) {
	if size > t.Size() {
		return Hash{}, ErrSizeOutOfRange
	}
	return t.hashRange(0, size), nil
}

// InclusionProof returns PATH(index, D[0:size]) (RFC 9162 §2.1.3.1), the
// audit path of leaf index in the tree of the first size leaves, with the
// sibling nearest the leaf first. The path of a one-leaf tree is empty (and
// non-nil).
//
// It returns ErrSizeOutOfRange if size > Size(), and ErrIndexOutOfRange if
// index >= size.
func (t *Tree) InclusionProof(index, size uint64) ([]Hash, error) {
	if size > t.Size() {
		return nil, ErrSizeOutOfRange
	}
	if index >= size {
		return nil, ErrIndexOutOfRange
	}
	return t.path(index, 0, size, make([]Hash, 0, bits.Len64(size-1))), nil
}

// path appends PATH(m, D[lo:hi]) (RFC 9162 §2.1.3.1) to proof and returns
// it. m is relative to lo, and 0 <= m < hi-lo.
func (t *Tree) path(m, lo, hi uint64, proof []Hash) []Hash {
	n := hi - lo
	if n == 1 {
		return proof
	}
	k := splitPoint(n)
	if m < k {
		proof = t.path(m, lo, lo+k, proof)
		return append(proof, t.hashRange(lo+k, hi))
	}
	proof = t.path(m-k, lo+k, hi, proof)
	return append(proof, t.hashRange(lo, lo+k))
}

// ConsistencyProof returns PROOF(size1, D[0:size2]) (RFC 9162 §2.1.4.1), the
// proof that the tree of the first size1 leaves is a prefix of the tree of
// the first size2, with the hash of the deepest subtree first.
//
// It returns ErrSizeOutOfRange if size2 > Size() or size1 > size2. The RFC
// defines PROOF for 0 < size1 < size2 only; for size1 == 0 or size1 == size2
// there is nothing to prove, and the proof is empty (and non-nil), as
// docs/protocol/merkle.md §4 specifies.
func (t *Tree) ConsistencyProof(size1, size2 uint64) ([]Hash, error) {
	if size2 > t.Size() || size1 > size2 {
		return nil, ErrSizeOutOfRange
	}
	if size1 == 0 || size1 == size2 {
		return []Hash{}, nil
	}
	// The proof has at most ceil(log2(size2)) + 1 hashes (RFC 9162 §2.1.4.1).
	proof := make([]Hash, 0, bits.Len64(size2-1)+1)
	return t.subproof(size1, 0, size2, true, proof), nil
}

// subproof appends SUBPROOF(m, D[lo:hi], b) (RFC 9162 §2.1.4.1) to proof and
// returns it, for 0 < m <= hi-lo. b is true while the recursion has only
// gone left, so D[lo:lo+m] is still the whole of D[0:size1]: if it is a
// complete subtree, the verifier already holds its head, root1.
//
// It visits the same ranges as MTH(D[0:size2]), so every range it hashes
// meets hashRange's precondition.
func (t *Tree) subproof(m, lo, hi uint64, b bool, proof []Hash) []Hash {
	n := hi - lo
	if m == n {
		if b {
			return proof
		}
		return append(proof, t.hashRange(lo, hi))
	}
	k := splitPoint(n)
	if m <= k {
		// D[lo+k:hi] exists only in the larger tree: prove the left
		// subtree and commit to the right one.
		proof = t.subproof(m, lo, lo+k, b, proof)
		return append(proof, t.hashRange(lo+k, hi))
	}
	// D[lo:lo+k] is the same in both trees: prove the right subtree and
	// commit to the left one.
	proof = t.subproof(m-k, lo+k, hi, false, proof)
	return append(proof, t.hashRange(lo, lo+k))
}

// hashRange returns MTH(D[lo:hi]) (RFC 9162 §2.1.1) for hi <= Size() and a
// range that the RFC's recursion visits when it starts from some D[0:n].
//
// Every such range starts at a multiple of the smallest power of two not
// below its length. So a range whose length is a power of two is a complete,
// aligned subtree, held in levels; any other range splits at k into one such
// subtree on the left and a shorter range of the same kind on the right.
func (t *Tree) hashRange(lo, hi uint64) Hash {
	n := hi - lo
	if n == 0 {
		return EmptyRoot()
	}
	if n&(n-1) == 0 {
		if lo&(n-1) != 0 {
			panic("merkle: hashRange called on an unaligned subtree")
		}
		level := bits.TrailingZeros64(n)
		return t.levels[level][lo>>level]
	}
	k := splitPoint(n)
	return NodeHash(t.hashRange(lo, lo+k), t.hashRange(lo+k, hi))
}

// splitPoint returns k, the largest power of two strictly less than n, for
// n >= 2 (RFC 9162 §2.1.1).
func splitPoint(n uint64) uint64 {
	return 1 << (bits.Len64(n-1) - 1)
}
