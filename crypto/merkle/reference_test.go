package merkle

import "crypto/sha256"

// This file is the test oracle. It transcribes RFC 9162 §2.1 directly and
// recursively, on raw leaf data, using crypto/sha256 only. It shares no code
// with the package under test, and returns plain [32]byte values rather than
// the package's Hash type.

// refK returns the largest power of two strictly less than n, for n > 1.
func refK(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// refMTH is MTH(D[n]) (RFC 9162 §2.1.1).
func refMTH(d [][]byte) [32]byte {
	switch len(d) {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return sha256.Sum256(append([]byte{0x00}, d[0]...))
	}
	k := refK(len(d))
	left, right := refMTH(d[:k]), refMTH(d[k:])
	buf := append([]byte{0x01}, left[:]...)
	buf = append(buf, right[:]...)
	return sha256.Sum256(buf)
}

// refPath is PATH(m, D[n]) (RFC 9162 §2.1.3.1), for 0 <= m < n.
func refPath(m int, d [][]byte) [][32]byte {
	n := len(d)
	if n == 1 {
		return nil
	}
	k := refK(n)
	if m < k {
		return append(refPath(m, d[:k]), refMTH(d[k:]))
	}
	return append(refPath(m-k, d[k:]), refMTH(d[:k]))
}

// refSubproof is SUBPROOF(m, D[n], b) (RFC 9162 §2.1.4.1), for 0 < m <= n.
// PROOF(m, D[n]) is refSubproof(m, D[n], true).
func refSubproof(m int, d [][]byte, b bool) [][32]byte {
	n := len(d)
	if m == n {
		if b {
			return nil
		}
		return [][32]byte{refMTH(d)}
	}
	k := refK(n)
	if m <= k {
		return append(refSubproof(m, d[:k], b), refMTH(d[k:]))
	}
	return append(refSubproof(m-k, d[k:], false), refMTH(d[:k]))
}
