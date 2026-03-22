package elgamal

import (
	"testing"

	"filippo.io/edwards25519"
)

func TestKeyGeneration(t *testing.T) {
	kp := GenerateKeyPair()
	if kp.PrivateKey == nil || kp.PublicKey == nil {
		t.Fatal("key pair fields should not be nil")
	}
	expected := new(edwards25519.Point).ScalarBaseMult(kp.PrivateKey)
	if expected.Equal(kp.PublicKey) != 1 {
		t.Fatal("public key should equal g^x")
	}
}

func TestEncryptDecryptZero(t *testing.T) {
	kp := GenerateKeyPair()
	ct, _ := Encrypt(kp.PublicKey, 0)
	m := Decrypt(kp.PrivateKey, ct)
	if m != 0 {
		t.Fatalf("expected 0, got %d", m)
	}
}

func TestEncryptDecryptOne(t *testing.T) {
	kp := GenerateKeyPair()
	ct, _ := Encrypt(kp.PublicKey, 1)
	m := Decrypt(kp.PrivateKey, ct)
	if m != 1 {
		t.Fatalf("expected 1, got %d", m)
	}
}

func TestHomomorphicAddition(t *testing.T) {
	kp := GenerateKeyPair()
	ct1, _ := Encrypt(kp.PublicKey, 1)
	ct2, _ := Encrypt(kp.PublicKey, 1)
	ct3, _ := Encrypt(kp.PublicKey, 0)
	sum := HomomorphicAdd(ct1, ct2, ct3)
	m := Decrypt(kp.PrivateKey, sum)
	if m != 2 {
		t.Fatalf("expected 2, got %d", m)
	}
}

func TestHomomorphicTally(t *testing.T) {
	kp := GenerateKeyPair()
	cts := make([]*Ciphertext, 100)
	for i := 0; i < 100; i++ {
		if i < 60 {
			cts[i], _ = Encrypt(kp.PublicKey, 1)
		} else {
			cts[i], _ = Encrypt(kp.PublicKey, 0)
		}
	}
	sum := HomomorphicAdd(cts...)
	m := Decrypt(kp.PrivateKey, sum)
	if m != 60 {
		t.Fatalf("expected 60, got %d", m)
	}
}

func TestHomomorphicAddEmpty(t *testing.T) {
	result := HomomorphicAdd()
	if result != nil {
		t.Fatal("HomomorphicAdd with no args should return nil")
	}
}

func TestCiphertextSerialization(t *testing.T) {
	kp := GenerateKeyPair()
	ct, _ := Encrypt(kp.PublicKey, 1)
	data := ct.Bytes()
	ct2, err := CiphertextFromBytes(data)
	if err != nil {
		t.Fatalf("deserialization failed: %v", err)
	}
	m := Decrypt(kp.PrivateKey, ct2)
	if m != 1 {
		t.Fatalf("expected 1 after round-trip, got %d", m)
	}
}

func TestEncryptReturnsRandomness(t *testing.T) {
	kp := GenerateKeyPair()
	ct, r := Encrypt(kp.PublicKey, 1)
	// Verify r produces the same ciphertext
	ct2 := EncryptWithRandomness(kp.PublicKey, 1, r)
	if ct.C1.Equal(ct2.C1) != 1 || ct.C2.Equal(ct2.C2) != 1 {
		t.Fatal("Encrypt and EncryptWithRandomness with same r should produce same ciphertext")
	}
}
