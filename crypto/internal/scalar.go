package internal

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"

	"github.com/gtank/ristretto255"
)

// uniformScalar reduces a 64-byte digest to a scalar. SetUniformBytes fails
// only when the input is not exactly 64 bytes, which every caller guarantees.
func uniformScalar(digest [64]byte) *ristretto255.Scalar {
	s, err := ristretto255.NewScalar().SetUniformBytes(digest[:])
	if err != nil {
		panic("SetUniformBytes failed: " + err.Error())
	}
	return s
}

// RandomScalar generates a cryptographically random scalar in Z_l.
// A crypto/rand failure is unrecoverable and panics.
func RandomScalar() *ristretto255.Scalar {
	var buf [64]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return uniformScalar(buf)
}

// FiatShamir computes a non-interactive challenge for Sigma protocols.
// Domain separator prevents cross-protocol attacks. The byte format is
// specified in docs/protocol/fiat-shamir.md.
func FiatShamir(domain string, data ...[]byte) *ristretto255.Scalar {
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
	return uniformScalar(digest)
}

// SumScalars adds all scalars together.
func SumScalars(scalars []*ristretto255.Scalar) *ristretto255.Scalar {
	sum := ristretto255.NewScalar()
	for _, s := range scalars {
		sum.Add(sum, s)
	}
	return sum
}
