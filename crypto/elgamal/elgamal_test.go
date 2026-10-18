package elgamal

import (
	"errors"
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

func mustEncrypt(t *testing.T, pk *ristretto255.Element, m int) (*Ciphertext, *ristretto255.Scalar) {
	t.Helper()
	ct, r, err := Encrypt(pk, m)
	if err != nil {
		t.Fatal(err)
	}
	return ct, r
}

func TestKeyGeneration(t *testing.T) {
	kp := GenerateKeyPair()
	if kp.PrivateKey == nil || kp.PublicKey == nil {
		t.Fatal("key pair fields should not be nil")
	}
	expected := ristretto255.NewIdentityElement().ScalarBaseMult(kp.PrivateKey)
	if expected.Equal(kp.PublicKey) != 1 {
		t.Fatal("public key should equal g^x")
	}
}

func TestEncryptDecryptZero(t *testing.T) {
	kp := GenerateKeyPair()
	ct, _ := mustEncrypt(t, kp.PublicKey, 0)
	m := Decrypt(kp.PrivateKey, ct)
	if m != 0 {
		t.Fatalf("expected 0, got %d", m)
	}
}

func TestEncryptDecryptOne(t *testing.T) {
	kp := GenerateKeyPair()
	ct, _ := mustEncrypt(t, kp.PublicKey, 1)
	m := Decrypt(kp.PrivateKey, ct)
	if m != 1 {
		t.Fatalf("expected 1, got %d", m)
	}
}

func TestHomomorphicAddition(t *testing.T) {
	kp := GenerateKeyPair()
	ct1, _ := mustEncrypt(t, kp.PublicKey, 1)
	ct2, _ := mustEncrypt(t, kp.PublicKey, 1)
	ct3, _ := mustEncrypt(t, kp.PublicKey, 0)
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
			cts[i], _ = mustEncrypt(t, kp.PublicKey, 1)
		} else {
			cts[i], _ = mustEncrypt(t, kp.PublicKey, 0)
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
	ct, _ := mustEncrypt(t, kp.PublicKey, 1)
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
	ct, r := mustEncrypt(t, kp.PublicKey, 1)
	// Verify r produces the same ciphertext
	ct2, err := EncryptWithRandomness(kp.PublicKey, 1, r)
	if err != nil {
		t.Fatal(err)
	}
	if ct.C1.Equal(ct2.C1) != 1 || ct.C2.Equal(ct2.C2) != 1 {
		t.Fatal("Encrypt and EncryptWithRandomness with same r should produce same ciphertext")
	}
}

func TestEncryptRejectsBadPublicKey(t *testing.T) {
	identity := ristretto255.NewIdentityElement()
	r := internal.RandomScalar()
	for name, pk := range map[string]*ristretto255.Element{"nil": nil, "identity": identity} {
		if _, _, err := Encrypt(pk, 1); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("Encrypt with %s key: err = %v, want ErrInvalidPublicKey", name, err)
		}
		if _, err := EncryptWithRandomness(pk, 1, r); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("EncryptWithRandomness with %s key: err = %v, want ErrInvalidPublicKey", name, err)
		}
	}
	if _, err := EncryptWithRandomness(GenerateKeyPair().PublicKey, 1, nil); err == nil {
		t.Error("EncryptWithRandomness with nil r: want error")
	}
}

// A zero r makes c1 the identity and c2 = g^m, which reveals m; the TS client
// refuses it too, and CiphertextFromBytes would reject the output.
func TestEncryptRejectsZeroRandomness(t *testing.T) {
	pk := GenerateKeyPair().PublicKey
	for _, m := range []int{0, 1} {
		ct, err := EncryptWithRandomness(pk, m, ristretto255.NewScalar())
		if !errors.Is(err, ErrInvalidRandomness) {
			t.Fatalf("EncryptWithRandomness(m=%d, r=0): err = %v, want ErrInvalidRandomness", m, err)
		}
		if ct != nil {
			t.Fatalf("EncryptWithRandomness(m=%d, r=0): ciphertext must be nil on error", m)
		}
	}
	if _, err := EncryptWithRandomness(pk, 1, nil); !errors.Is(err, ErrInvalidRandomness) {
		t.Fatalf("EncryptWithRandomness(r=nil): err = %v, want ErrInvalidRandomness", err)
	}
}
