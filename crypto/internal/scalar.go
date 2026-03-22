package internal

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"

	"filippo.io/edwards25519"
)

// RandomScalar generates a cryptographically random scalar in Z_q.
func RandomScalar() *edwards25519.Scalar {
	var buf [64]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	s, err := edwards25519.NewScalar().SetUniformBytes(buf[:])
	if err != nil {
		panic("SetUniformBytes failed: " + err.Error())
	}
	return s
}

// HashToScalar hashes a domain separator and arbitrary data to a scalar.
func HashToScalar(domain, data []byte) *edwards25519.Scalar {
	h := sha512.New()
	h.Write(domain)
	h.Write(data)
	var digest [64]byte
	copy(digest[:], h.Sum(nil))
	s, err := edwards25519.NewScalar().SetUniformBytes(digest[:])
	if err != nil {
		panic("SetUniformBytes failed: " + err.Error())
	}
	return s
}

// FiatShamir computes a non-interactive challenge for Sigma protocols.
// Domain separator prevents cross-protocol attacks.
func FiatShamir(domain string, data ...[]byte) *edwards25519.Scalar {
	h := sha512.New()
	// Write domain with length prefix
	domainBytes := []byte(domain)
	binary.Write(h, binary.BigEndian, uint32(len(domainBytes)))
	h.Write(domainBytes)
	// Write each data element with length prefix
	for _, d := range data {
		binary.Write(h, binary.BigEndian, uint32(len(d)))
		h.Write(d)
	}
	var digest [64]byte
	copy(digest[:], h.Sum(nil))
	s, err := edwards25519.NewScalar().SetUniformBytes(digest[:])
	if err != nil {
		panic("SetUniformBytes failed: " + err.Error())
	}
	return s
}

// SumScalars adds all scalars together.
func SumScalars(scalars []*edwards25519.Scalar) *edwards25519.Scalar {
	sum := edwards25519.NewScalar()
	for _, s := range scalars {
		sum.Add(sum, s)
	}
	return sum
}
