package threshold

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
)

func TestPartialDecryptAndCombine(t *testing.T) {
	dealer := NewDealer(5, 9)
	pk := dealer.PublicKey()
	ct, _ := elgamal.Encrypt(pk, 42)

	indices := []int{1, 3, 5, 7, 9}
	partials := make([]*PartialDecryption, 5)
	for i, idx := range indices {
		partials[i] = PartialDecrypt(dealer.Shares[idx-1], ct)
	}

	m := CombinePartials(ct, partials, indices, 100)
	if m != 42 {
		t.Fatalf("expected 42, got %d", m)
	}
}

func TestPartialDecryptionProof(t *testing.T) {
	dealer := NewDealer(5, 9)
	pk := dealer.PublicKey()
	ct, _ := elgamal.Encrypt(pk, 1)

	share := dealer.Shares[0]
	vk := new(edwards25519.Point).ScalarBaseMult(share)

	pd := PartialDecryptWithProof(share, ct, vk)
	if !VerifyPartialDecryption(ct, pd, vk) {
		t.Fatal("valid partial decryption proof should verify")
	}
}

func TestPartialDecryptionProofInvalid(t *testing.T) {
	dealer := NewDealer(5, 9)
	pk := dealer.PublicKey()
	ct, _ := elgamal.Encrypt(pk, 1)

	share := dealer.Shares[0]
	wrongVK := new(edwards25519.Point).ScalarBaseMult(dealer.Shares[1]) // wrong key

	pd := PartialDecryptWithProof(share, ct, wrongVK)
	// The proof was generated with wrongVK but share doesn't match it
	// Actually the prover uses share as x and wrongVK as A=g^x_wrong
	// So proof proves log_g(wrongVK) == log_{c1}(d) but wrongVK != g^share
	// This should fail
	if VerifyPartialDecryption(ct, pd, wrongVK) {
		t.Fatal("proof with wrong verification key should NOT verify")
	}
}
