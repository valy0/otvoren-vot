package proof

import (
	"testing"

	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

func TestBinaryProofZero(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	r := internal.RandomScalar()
	ct := elgamal.EncryptWithRandomness(kp.PublicKey, 0, r)
	proof := ProveBinary(kp.PublicKey, ct, 0, r)
	if !VerifyBinary(kp.PublicKey, ct, proof) {
		t.Fatal("valid proof for 0 should verify")
	}
}

func TestBinaryProofOne(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	r := internal.RandomScalar()
	ct := elgamal.EncryptWithRandomness(kp.PublicKey, 1, r)
	proof := ProveBinary(kp.PublicKey, ct, 1, r)
	if !VerifyBinary(kp.PublicKey, ct, proof) {
		t.Fatal("valid proof for 1 should verify")
	}
}

func TestBinaryProofWrongMessage(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	r := internal.RandomScalar()
	ct := elgamal.EncryptWithRandomness(kp.PublicKey, 1, r)
	// Claim it's 0 when it's 1
	proof := ProveBinary(kp.PublicKey, ct, 0, r)
	if VerifyBinary(kp.PublicKey, ct, proof) {
		t.Fatal("proof for wrong message should NOT verify")
	}
}

func TestBinaryProofTamperedCiphertext(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	r := internal.RandomScalar()
	ct := elgamal.EncryptWithRandomness(kp.PublicKey, 1, r)
	proof := ProveBinary(kp.PublicKey, ct, 1, r)
	ct2, _ := elgamal.Encrypt(kp.PublicKey, 0)
	if VerifyBinary(kp.PublicKey, ct2, proof) {
		t.Fatal("proof should not verify against different ciphertext")
	}
}

func TestBinaryProofWrongPublicKey(t *testing.T) {
	kp1 := elgamal.GenerateKeyPair()
	kp2 := elgamal.GenerateKeyPair()
	r := internal.RandomScalar()
	ct := elgamal.EncryptWithRandomness(kp1.PublicKey, 1, r)
	proof := ProveBinary(kp1.PublicKey, ct, 1, r)
	// Verify with wrong public key — should fail due to PK in Fiat-Shamir
	if VerifyBinary(kp2.PublicKey, ct, proof) {
		t.Fatal("proof should not verify with different public key")
	}
}
