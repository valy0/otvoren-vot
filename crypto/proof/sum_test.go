package proof

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

func TestSumProofValid(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	n := 5
	selected := 2
	cts := make([]*elgamal.Ciphertext, n)
	rs := make([]*edwards25519.Scalar, n)
	for i := range n {
		r := internal.RandomScalar()
		m := 0
		if i == selected {
			m = 1
		}
		cts[i] = elgamal.EncryptWithRandomness(kp.PublicKey, m, r)
		rs[i] = r
	}
	rSum := internal.SumScalars(rs)

	p := ProveSumOne(kp.PublicKey, cts, rSum)
	if !VerifySumOne(kp.PublicKey, cts, p) {
		t.Fatal("valid sum-to-one proof should verify")
	}
}

func TestSumProofInvalidSumZero(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	cts := make([]*elgamal.Ciphertext, 3)
	rs := make([]*edwards25519.Scalar, 3)
	for i := range 3 {
		r := internal.RandomScalar()
		cts[i] = elgamal.EncryptWithRandomness(kp.PublicKey, 0, r) // all zeros
		rs[i] = r
	}
	rSum := internal.SumScalars(rs)
	p := ProveSumOne(kp.PublicKey, cts, rSum)
	if VerifySumOne(kp.PublicKey, cts, p) {
		t.Fatal("sum-to-zero should NOT verify as sum-to-one")
	}
}

func TestSumProofInvalidSumTwo(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	cts := make([]*elgamal.Ciphertext, 3)
	rs := make([]*edwards25519.Scalar, 3)
	for i := range 3 {
		r := internal.RandomScalar()
		m := 0
		if i < 2 {
			m = 1 // two ones = sum is 2
		}
		cts[i] = elgamal.EncryptWithRandomness(kp.PublicKey, m, r)
		rs[i] = r
	}
	rSum := internal.SumScalars(rs)
	p := ProveSumOne(kp.PublicKey, cts, rSum)
	if VerifySumOne(kp.PublicKey, cts, p) {
		t.Fatal("sum-to-two should NOT verify as sum-to-one")
	}
}

func TestSumProofWithBallot(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	ballot := elgamal.EncodeBallot(kp.PublicKey, 5, 2)
	rSum := internal.SumScalars(ballot.PartyRandomness)
	p := ProveSumOne(kp.PublicKey, ballot.PartyVector, rSum)
	if !VerifySumOne(kp.PublicKey, ballot.PartyVector, p) {
		t.Fatal("ballot party vector should have sum-to-one proof verify")
	}
}
