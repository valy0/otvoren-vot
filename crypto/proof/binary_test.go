package proof

import (
	"testing"

	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

func TestBinaryProofZero(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	r := internal.RandomScalar()
	ct := mustEncrypt(t, kp.PublicKey, 0, r)
	proof, err := ProveBinary(testCtx(0), kp.PublicKey, ct, 0, r)
	if err != nil {
		t.Fatalf("ProveBinary: %v", err)
	}
	requireValid(t, VerifyBinary(testCtx(0), kp.PublicKey, ct, proof), "valid proof for 0 should verify")
}

func TestBinaryProofOne(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	r := internal.RandomScalar()
	ct := mustEncrypt(t, kp.PublicKey, 1, r)
	proof, err := ProveBinary(testCtx(0), kp.PublicKey, ct, 1, r)
	if err != nil {
		t.Fatalf("ProveBinary: %v", err)
	}
	requireValid(t, VerifyBinary(testCtx(0), kp.PublicKey, ct, proof), "valid proof for 1 should verify")
}

func TestBinaryProofWrongMessage(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	r := internal.RandomScalar()
	ct := mustEncrypt(t, kp.PublicKey, 1, r)
	// Claim it's 0 when it's 1
	proof, err := ProveBinary(testCtx(0), kp.PublicKey, ct, 0, r)
	if err != nil {
		t.Fatalf("ProveBinary: %v", err)
	}
	requireInvalid(t, VerifyBinary(testCtx(0), kp.PublicKey, ct, proof), "proof for wrong message should NOT verify")
}

func TestBinaryProofTamperedCiphertext(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	r := internal.RandomScalar()
	ct := mustEncrypt(t, kp.PublicKey, 1, r)
	proof, err := ProveBinary(testCtx(0), kp.PublicKey, ct, 1, r)
	if err != nil {
		t.Fatalf("ProveBinary: %v", err)
	}
	ct2, _, err := elgamal.Encrypt(kp.PublicKey, 0)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	requireInvalid(t, VerifyBinary(testCtx(0), kp.PublicKey, ct2, proof), "proof should not verify against different ciphertext")
}

func TestBinaryProofWrongPublicKey(t *testing.T) {
	kp1 := elgamal.GenerateKeyPair()
	kp2 := elgamal.GenerateKeyPair()
	r := internal.RandomScalar()
	ct := mustEncrypt(t, kp1.PublicKey, 1, r)
	proof, err := ProveBinary(testCtx(0), kp1.PublicKey, ct, 1, r)
	if err != nil {
		t.Fatalf("ProveBinary: %v", err)
	}
	// Verify with wrong public key — should fail due to PK in Fiat-Shamir
	requireInvalid(t, VerifyBinary(testCtx(0), kp2.PublicKey, ct, proof), "proof should not verify with different public key")
}
