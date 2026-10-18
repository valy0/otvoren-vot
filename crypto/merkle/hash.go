// Package merkle is the bulletin board's append-only SHA-256 Merkle tree: the
// RFC 9162 §2.1 tree, without modification. docs/protocol/merkle.md is the
// normative specification.
package merkle

import (
	"crypto/sha256"
	"errors"
)

// HashSize is the size in bytes of every hash in the tree. The tree hashes
// with SHA-256 (RFC 9162 §2.1).
const HashSize = sha256.Size

// Hash is a SHA-256 digest: a leaf hash, an interior node hash or a tree head
// (RFC 9162 §2.1.1).
type Hash [HashSize]byte

var (
	// ErrIndexOutOfRange reports a leaf index that is not below the tree
	// size, including any index into an empty tree (RFC 9162 §2.1.3.2 step 1).
	ErrIndexOutOfRange = errors.New("merkle: leaf index out of range")

	// ErrSizeOutOfRange reports a tree size the tree has not reached, so
	// there is no D[0:size] to compute a head or proof from (RFC 9162 §2.1.1),
	// or a consistency proof asked for or offered from a larger tree to a
	// smaller one (docs/protocol/merkle.md §4).
	ErrSizeOutOfRange = errors.New("merkle: tree size out of range")

	// ErrInvalidProof reports a proof that fails verification: it has the
	// wrong length for its index and size, or for its two sizes, or it does
	// not hash to the expected root or roots (RFC 9162 §2.1.3.2, §2.1.4.2).
	ErrInvalidProof = errors.New("merkle: invalid proof")
)

// Domain-separation prefixes (RFC 9162 §2.1.1): a leaf hash can never be
// presented as an interior node hash, or the other way round.
const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// LeafHash returns SHA-256(0x00 ‖ data), the hash of a leaf (RFC 9162 §2.1.1).
func LeafHash(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(data)
	var out Hash
	h.Sum(out[:0])
	return out
}

// NodeHash returns SHA-256(0x01 ‖ left ‖ right), the hash of an interior
// node (RFC 9162 §2.1.1).
func NodeHash(left, right Hash) Hash {
	var buf [1 + 2*HashSize]byte
	buf[0] = nodePrefix
	copy(buf[1:], left[:])
	copy(buf[1+HashSize:], right[:])
	return sha256.Sum256(buf[:])
}

// EmptyRoot returns SHA-256(""), the head of the empty tree (RFC 9162 §2.1.1).
func EmptyRoot() Hash {
	return sha256.Sum256(nil)
}
