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
