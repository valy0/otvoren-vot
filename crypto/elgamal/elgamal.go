package elgamal

import (
	"fmt"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/group"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

// KeyPair holds an ElGamal key pair over Ristretto255.
type KeyPair struct {
	PrivateKey *ristretto255.Scalar
	PublicKey  *ristretto255.Element
}

// GenerateKeyPair creates a fresh ElGamal key pair.
func GenerateKeyPair() *KeyPair {
	x := internal.RandomScalar()
	h := ristretto255.NewIdentityElement().ScalarBaseMult(x)
	return &KeyPair{PrivateKey: x, PublicKey: h}
}

// KeyPairFromSecret creates a key pair from an existing private key.
func KeyPairFromSecret(x *ristretto255.Scalar) *KeyPair {
	h := ristretto255.NewIdentityElement().ScalarBaseMult(x)
	return &KeyPair{PrivateKey: x, PublicKey: h}
}

// Ciphertext is an exponential ElGamal ciphertext (c1, c2).
// c1 = g^r, c2 = h^r * g^m
type Ciphertext struct {
	C1 *ristretto255.Element
	C2 *ristretto255.Element
}

const MaxDecrypt = 5_000_000

// Encrypt encrypts a small integer m under the given public key.
func Encrypt(publicKey *ristretto255.Element, m int) (*Ciphertext, *ristretto255.Scalar, error) {
	r := internal.RandomScalar()
	ct, err := EncryptWithRandomness(publicKey, m, r)
	if err != nil {
		return nil, nil, err
	}
	return ct, r, nil
}

// EncryptWithRandomness encrypts m with explicit randomness r.
func EncryptWithRandomness(publicKey *ristretto255.Element, m int, r *ristretto255.Scalar) (*Ciphertext, error) {
	gm, err := internal.ScalarBaseMultInt(m)
	if err != nil {
		return nil, fmt.Errorf("encrypting plaintext: %w", err)
	}
	c1 := ristretto255.NewIdentityElement().ScalarBaseMult(r)
	hr := ristretto255.NewIdentityElement().ScalarMult(r, publicKey)
	c2 := ristretto255.NewIdentityElement().Add(hr, gm)
	return &Ciphertext{C1: c1, C2: c2}, nil
}

// HomomorphicAdd combines ciphertexts. Result encrypts the sum of plaintexts.
func HomomorphicAdd(cts ...*Ciphertext) *Ciphertext {
	if len(cts) == 0 {
		return nil
	}
	sumC1 := ristretto255.NewIdentityElement().Set(cts[0].C1)
	sumC2 := ristretto255.NewIdentityElement().Set(cts[0].C2)
	for _, ct := range cts[1:] {
		sumC1.Add(sumC1, ct.C1)
		sumC2.Add(sumC2, ct.C2)
	}
	return &Ciphertext{C1: sumC1, C2: sumC2}
}

// Decrypt recovers the plaintext using the full private key.
// Uses BSGS for discrete log recovery. Only works for m in [0, MaxDecrypt].
// Returns -1 if plaintext is out of range.
func Decrypt(privateKey *ristretto255.Scalar, ct *Ciphertext) int {
	s := ristretto255.NewIdentityElement().ScalarMult(privateKey, ct.C1)
	s.Negate(s)
	gm := ristretto255.NewIdentityElement().Add(ct.C2, s)
	return internal.BabyStepGiantStep(gm, MaxDecrypt)
}

// Bytes serializes the ciphertext to 64 bytes.
func (ct *Ciphertext) Bytes() []byte {
	out := make([]byte, 64)
	copy(out[:32], ct.C1.Bytes())
	copy(out[32:], ct.C2.Bytes())
	return out
}

// CiphertextFromBytes deserializes a ciphertext from 64 bytes. Both halves
// must be canonical, non-identity elements (see group.DecodeElement).
func CiphertextFromBytes(data []byte) (*Ciphertext, error) {
	if len(data) != 64 {
		return nil, fmt.Errorf("ciphertext has %d bytes, want 64: %w", len(data), group.ErrLength)
	}
	c1, err := group.DecodeElement(data[:32])
	if err != nil {
		return nil, fmt.Errorf("ciphertext c1: %w", err)
	}
	c2, err := group.DecodeElement(data[32:])
	if err != nil {
		return nil, fmt.Errorf("ciphertext c2: %w", err)
	}
	return &Ciphertext{C1: c1, C2: c2}, nil
}
