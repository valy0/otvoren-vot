// Package group is the single gate through which every wire point and scalar
// enters the Ristretto255 group. Decoders reject wrong-length, non-canonical
// and identity encodings.
package group

import (
	"errors"
	"fmt"

	"github.com/gtank/ristretto255"
)

const (
	// ElementSize is the encoded size of a group element in bytes.
	ElementSize = 32
	// ScalarSize is the encoded size of a scalar in bytes.
	ScalarSize = 32
)

var (
	// ErrLength is returned for an input that is not exactly 32 bytes.
	ErrLength = errors.New("group: wrong encoding length")
	// ErrNonCanonical is returned for an encoding that is not canonical
	// (non-canonical field element, negative, non-square, scalar >= l, ...).
	ErrNonCanonical = errors.New("group: non-canonical encoding")
	// ErrIdentity is returned for the identity element's encoding.
	ErrIdentity = errors.New("group: identity element")
)

// DecodeElement decodes exactly 32 bytes as a canonical ristretto255 element
// and rejects the identity.
func DecodeElement(b []byte) (*ristretto255.Element, error) {
	if len(b) != ElementSize {
		return nil, fmt.Errorf("element has %d bytes, want %d: %w", len(b), ElementSize, ErrLength)
	}
	e, err := ristretto255.NewIdentityElement().SetCanonicalBytes(b)
	if err != nil {
		return nil, fmt.Errorf("decoding element: %w", ErrNonCanonical)
	}
	if e.Equal(ristretto255.NewIdentityElement()) == 1 {
		return nil, fmt.Errorf("decoding element: %w", ErrIdentity)
	}
	return e, nil
}

// DecodeScalar decodes exactly 32 bytes as a canonical scalar (< l).
func DecodeScalar(b []byte) (*ristretto255.Scalar, error) {
	if len(b) != ScalarSize {
		return nil, fmt.Errorf("scalar has %d bytes, want %d: %w", len(b), ScalarSize, ErrLength)
	}
	s, err := ristretto255.NewScalar().SetCanonicalBytes(b)
	if err != nil {
		return nil, fmt.Errorf("decoding scalar: %w", ErrNonCanonical)
	}
	return s, nil
}
