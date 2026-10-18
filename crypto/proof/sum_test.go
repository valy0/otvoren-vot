package proof

import (
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

func TestSumProofValid(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	n := 5
	selected := 2
	cts := make([]*elgamal.Ciphertext, n)
	rs := make([]*ristretto255.Scalar, n)
	for i := range n {
		r := internal.RandomScalar()
		m := 0
		if i == selected {
			m = 1
		}
		cts[i] = mustEncrypt(t, kp.PublicKey, m, r)
		rs[i] = r
	}
	rSum := internal.SumScalars(rs)

	p, err := ProveSumOne(testCtx(0), kp.PublicKey, cts, rSum)
	if err != nil {
		t.Fatalf("ProveSumOne: %v", err)
	}
	requireValid(t, VerifySumOne(testCtx(0), kp.PublicKey, cts, p), "valid sum-to-one proof should verify")
}

func TestSumProofInvalidSumZero(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	cts := make([]*elgamal.Ciphertext, 3)
	rs := make([]*ristretto255.Scalar, 3)
	for i := range 3 {
		r := internal.RandomScalar()
		cts[i] = mustEncrypt(t, kp.PublicKey, 0, r) // all zeros
		rs[i] = r
	}
	rSum := internal.SumScalars(rs)
	p, err := ProveSumOne(testCtx(0), kp.PublicKey, cts, rSum)
	if err != nil {
		t.Fatalf("ProveSumOne: %v", err)
	}
	requireInvalid(t, VerifySumOne(testCtx(0), kp.PublicKey, cts, p), "sum-to-zero should NOT verify as sum-to-one")
}

func TestSumProofInvalidSumTwo(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	cts := make([]*elgamal.Ciphertext, 3)
	rs := make([]*ristretto255.Scalar, 3)
	for i := range 3 {
		r := internal.RandomScalar()
		m := 0
		if i < 2 {
			m = 1 // two ones = sum is 2
		}
		cts[i] = mustEncrypt(t, kp.PublicKey, m, r)
		rs[i] = r
	}
	rSum := internal.SumScalars(rs)
	p, err := ProveSumOne(testCtx(0), kp.PublicKey, cts, rSum)
	if err != nil {
		t.Fatalf("ProveSumOne: %v", err)
	}
	requireInvalid(t, VerifySumOne(testCtx(0), kp.PublicKey, cts, p), "sum-to-two should NOT verify as sum-to-one")
}

func TestSumProofWithBallot(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	ballot, err := elgamal.EncodeBallot(kp.PublicKey, 5, 2)
	if err != nil {
		t.Fatalf("EncodeBallot: %v", err)
	}
	rSum := internal.SumScalars(ballot.PartyRandomness)
	p, err := ProveSumOne(testCtx(0), kp.PublicKey, ballot.PartyVector, rSum)
	if err != nil {
		t.Fatalf("ProveSumOne: %v", err)
	}
	requireValid(t, VerifySumOne(testCtx(0), kp.PublicKey, ballot.PartyVector, p), "ballot party vector should have sum-to-one proof verify")
}
