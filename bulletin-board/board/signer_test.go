package board

import (
	"testing"

	"github.com/valy0/otvoren-vot/crypto/merkle"
)

func TestSignAndVerify(t *testing.T) {
	signer := NewSigner(nil) // dev key

	// Create a minimal board (no DB needed for signing)
	b := &Board{tree: merkle.New()}

	sr, err := signer.SignRoot(b)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sr.RootSHA256 != "" {
		t.Fatal("empty board should have empty root")
	}
	if !VerifySignature(signer.PublicKey(), sr) {
		t.Fatal("signature should verify")
	}
}

func TestSignAfterAppend(t *testing.T) {
	signer := NewSigner(nil)
	b := &Board{tree: merkle.New()}
	b.tree.Append([]byte("test-ballot"))

	sr, err := signer.SignRoot(b)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sr.RootSHA256 == "" {
		t.Fatal("root should not be empty")
	}
	if sr.BallotCount != 1 {
		t.Fatalf("expected count 1, got %d", sr.BallotCount)
	}
	if !VerifySignature(signer.PublicKey(), sr) {
		t.Fatal("signature should verify")
	}
}

func TestSignatureTampered(t *testing.T) {
	signer := NewSigner(nil)
	b := &Board{tree: merkle.New()}
	b.tree.Append([]byte("ballot"))

	sr, _ := signer.SignRoot(b)
	sr.BallotCount = 999 // tamper
	if VerifySignature(signer.PublicKey(), sr) {
		t.Fatal("tampered root should NOT verify")
	}
}
