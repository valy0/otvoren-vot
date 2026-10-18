package merkle

// VerifyInclusion checks that leafHash is leaf index of the tree of size
// leaves whose head is root, given proof, its audit path PATH(index,
// D[size]) with the sibling nearest the leaf first. It transcribes RFC 9162
// §2.1.3.2.
//
// The walk is driven by index and size-1, not by the proof, so the proof
// must have exactly the length that (index, size) implies and each hash is
// combined on the side that (index, size) dictates.
//
// It returns ErrIndexOutOfRange if index >= size, which includes size == 0,
// and ErrInvalidProof if the proof is too long or too short for (index,
// size) or does not hash to root. It never panics. Every pass of its loop
// shifts sn right, so it stops after at most 65 proof elements: its work is
// bounded by the proof length and the 64 bits of size, never by size's value.
func VerifyInclusion(leafHash Hash, index, size uint64, proof []Hash, root Hash) error {
	if index >= size {
		return ErrIndexOutOfRange
	}
	fn, sn := index, size-1
	r := leafHash
	for _, p := range proof {
		if sn == 0 {
			// More proof than the path from index to the root.
			return ErrInvalidProof
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			// Climb past the levels where this node has no right sibling.
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || r != root {
		// sn != 0: less proof than the path from index to the root.
		return ErrInvalidProof
	}
	return nil
}

// VerifyConsistency checks that the tree of size1 leaves whose head is root1
// is a prefix of the tree of size2 leaves whose head is root2, given proof,
// PROOF(size1, D[size2]) with the hash of the deepest subtree first.
//
// For 0 < size1 < size2 it transcribes RFC 9162 §2.1.4.2. The other sizes
// follow docs/protocol/merkle.md §4: size1 > size2 is rejected; size1 ==
// size2 needs an empty proof and root1 == root2; and size1 == 0 needs an
// empty proof and root1 == EmptyRoot(). (0, 0) meets both of the last two.
//
// As in VerifyInclusion, the walk is driven by size1-1 and size2-1, not by
// the proof, so the proof must have exactly the length that (size1, size2)
// implies.
//
// It returns ErrSizeOutOfRange if size1 > size2, and ErrInvalidProof if the
// proof is too long or too short for (size1, size2) or does not hash to
// both root1 and root2. It never panics. Every pass of its loop shifts sn
// right, so the loop makes at most 65 passes however long the proof is: its
// work is bounded by the proof length and the 64 bits of size2, never by
// the sizes' values.
func VerifyConsistency(size1, size2 uint64, root1, root2 Hash, proof []Hash) error {
	if size1 > size2 {
		return ErrSizeOutOfRange
	}
	if size1 == 0 || size1 == size2 {
		// Nothing to prove: D[0:0] is a prefix of every list, and every list
		// is a prefix of itself.
		if len(proof) != 0 {
			return ErrInvalidProof
		}
		if size1 == 0 && root1 != EmptyRoot() {
			return ErrInvalidProof
		}
		if size1 == size2 && root1 != root2 {
			return ErrInvalidProof
		}
		return nil
	}

	// Step 1. Every PROOF(size1, D[size2]) with size1 < size2 commits to at
	// least D[size1:size2], so it is never empty.
	if len(proof) == 0 {
		return ErrInvalidProof
	}
	// Step 2. When size1 is a power of two, D[0:size1] is a complete subtree
	// of the larger tree and the proof omits its head (SUBPROOF(m, D[m],
	// true) = {}). The walk starts from root1, as if it were prepended.
	start, rest := proof[0], proof[1:]
	if size1&(size1-1) == 0 {
		start, rest = root1, proof
	}
	// Step 3.
	fn, sn := size1-1, size2-1
	// Step 4. Climb past the levels where D[0:size1] ends on a right child.
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	// Step 5.
	fr, sr := start, start
	// Step 6.
	for _, c := range rest {
		if sn == 0 {
			// Step 6a: more proof than the path to the larger root.
			return ErrInvalidProof
		}
		if fn&1 == 1 || fn == sn {
			// Step 6b: c is a left sibling in both trees.
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			// c is a right sibling that only the larger tree has.
			sr = NodeHash(sr, c)
		}
		// Step 6c.
		fn >>= 1
		sn >>= 1
	}
	// Step 7. sn != 0: less proof than the path to the larger root.
	if fr != root1 || sr != root2 || sn != 0 {
		return ErrInvalidProof
	}
	return nil
}
