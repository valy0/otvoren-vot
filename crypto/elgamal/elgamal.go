package elgamal

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

// KeyPair holds an ElGamal key pair over Ristretto255.
type KeyPair struct {
	PrivateKey *edwards25519.Scalar
	PublicKey  *edwards25519.Point
}

// GenerateKeyPair creates a fresh ElGamal key pair.
func GenerateKeyPair() *KeyPair {
	x := internal.RandomScalar()
	h := new(edwards25519.Point).ScalarBaseMult(x)
	return &KeyPair{PrivateKey: x, PublicKey: h}
}

// KeyPairFromSecret creates a key pair from an existing private key.
func KeyPairFromSecret(x *edwards25519.Scalar) *KeyPair {
	h := new(edwards25519.Point).ScalarBaseMult(x)
	return &KeyPair{PrivateKey: x, PublicKey: h}
}

// Ciphertext is an exponential ElGamal ciphertext (c1, c2).
// c1 = g^r, c2 = h^r * g^m
type Ciphertext struct {
	C1 *edwards25519.Point
	C2 *edwards25519.Point
}

const MaxDecrypt = 5_000_000

// Encrypt encrypts a small integer m under the given public key.
func Encrypt(publicKey *edwards25519.Point, m int) (*Ciphertext, *edwards25519.Scalar) {
	r := internal.RandomScalar()
	ct := EncryptWithRandomness(publicKey, m, r)
	return ct, r
}

// EncryptWithRandomness encrypts m with explicit randomness r.
func EncryptWithRandomness(publicKey *edwards25519.Point, m int, r *edwards25519.Scalar) *Ciphertext {
	c1 := new(edwards25519.Point).ScalarBaseMult(r)
	hr := new(edwards25519.Point).ScalarMult(r, publicKey)
	gm := internal.ScalarBaseMultInt(m)
	c2 := new(edwards25519.Point).Add(hr, gm)
	return &Ciphertext{C1: c1, C2: c2}
}

// HomomorphicAdd combines ciphertexts. Result encrypts the sum of plaintexts.
func HomomorphicAdd(cts ...*Ciphertext) *Ciphertext {
	if len(cts) == 0 {
		return nil
	}
	sumC1 := new(edwards25519.Point).Set(cts[0].C1)
	sumC2 := new(edwards25519.Point).Set(cts[0].C2)
	for _, ct := range cts[1:] {
		sumC1.Add(sumC1, ct.C1)
		sumC2.Add(sumC2, ct.C2)
	}
	return &Ciphertext{C1: sumC1, C2: sumC2}
}

// Decrypt recovers the plaintext using the full private key.
// Uses BSGS for discrete log recovery. Only works for m in [0, MaxDecrypt].
// Returns -1 if plaintext is out of range.
func Decrypt(privateKey *edwards25519.Scalar, ct *Ciphertext) int {
	s := new(edwards25519.Point).ScalarMult(privateKey, ct.C1)
	s.Negate(s)
	gm := new(edwards25519.Point).Add(ct.C2, s)
	return internal.BabyStepGiantStep(gm, MaxDecrypt)
}

// Bytes serializes the ciphertext to 64 bytes.
func (ct *Ciphertext) Bytes() []byte {
	out := make([]byte, 64)
	copy(out[:32], ct.C1.Bytes())
	copy(out[32:], ct.C2.Bytes())
	return out
}

// CiphertextFromBytes deserializes a ciphertext from 64 bytes.
func CiphertextFromBytes(data []byte) (*Ciphertext, error) {
	if len(data) != 64 {
		return nil, errors.New("ciphertext must be 64 bytes")
	}
	c1, err := new(edwards25519.Point).SetBytes(data[:32])
	if err != nil {
		return nil, err
	}
	c2, err := new(edwards25519.Point).SetBytes(data[32:])
	if err != nil {
		return nil, err
	}
	return &Ciphertext{C1: c1, C2: c2}, nil
}
