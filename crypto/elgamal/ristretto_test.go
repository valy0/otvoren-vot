package elgamal

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/group"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

func smallScalar(t *testing.T, k int) *ristretto255.Scalar {
	t.Helper()
	s, err := internal.ScalarFromInt(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEncryptMatchesRFC9496Multiples(t *testing.T) {
	raw, err := os.ReadFile("../group/testdata/rfc9496.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Multiples []string `json:"multiples"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	pk := ristretto255.NewIdentityElement().ScalarBaseMult(smallScalar(t, 2))
	ct, err := EncryptWithRandomness(pk, 1, smallScalar(t, 3))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(ct.C1.Bytes()); got != v.Multiples[3] {
		t.Errorf("c1 = %s, want 3G = %s", got, v.Multiples[3])
	}
	if got := hex.EncodeToString(ct.C2.Bytes()); got != v.Multiples[7] {
		t.Errorf("c2 = %s, want 7G = %s", got, v.Multiples[7])
	}
}

func TestNegativePlaintextRejected(t *testing.T) {
	kp := GenerateKeyPair()
	r := internal.RandomScalar()
	ct, err := EncryptWithRandomness(kp.PublicKey, -3, r)
	if !errors.Is(err, internal.ErrNegative) {
		t.Fatalf("EncryptWithRandomness(-3) err = %v, want ErrNegative", err)
	}
	if ct != nil {
		t.Fatal("ciphertext must be nil on error")
	}
	if _, _, err := Encrypt(kp.PublicKey, -1); !errors.Is(err, internal.ErrNegative) {
		t.Fatalf("Encrypt(-1) err = %v, want ErrNegative", err)
	}
	if _, err := internal.ScalarFromInt(-1); !errors.Is(err, internal.ErrNegative) {
		t.Fatalf("ScalarFromInt(-1) err = %v, want ErrNegative", err)
	}
}

func TestCiphertextFromBytesRejectsIdentityC1(t *testing.T) {
	kp := GenerateKeyPair()
	valid := kp.PublicKey.Bytes()
	data := append(make([]byte, 32), valid...)
	_, err := CiphertextFromBytes(data)
	if !errors.Is(err, group.ErrIdentity) {
		t.Fatalf("err = %v, want group.ErrIdentity", err)
	}
	if _, err := CiphertextFromBytes(data[:63]); !errors.Is(err, group.ErrLength) {
		t.Fatalf("short input err = %v, want group.ErrLength", err)
	}
}

func TestTallyBallotsShapeMismatch(t *testing.T) {
	kp := GenerateKeyPair()
	mustBallot := func(b *Ballot, err error) *Ballot {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	three := mustBallot(EncodeBallot(kp.PublicKey, 3, 0))
	four := mustBallot(EncodeBallot(kp.PublicKey, 4, 0))
	if _, err := TallyBallots([]*Ballot{three, four}); !errors.Is(err, ErrShapeMismatch) {
		t.Errorf("party count mismatch err = %v", err)
	}
	withCand := mustBallot(EncodeBallotWithCandidates(kp.PublicKey, 3, 2, 0, 1))
	if _, err := TallyBallots([]*Ballot{three, withCand}); !errors.Is(err, ErrShapeMismatch) {
		t.Errorf("without-then-with candidates err = %v", err)
	}
	if _, err := TallyBallots([]*Ballot{withCand, three}); !errors.Is(err, ErrShapeMismatch) {
		t.Errorf("with-then-without candidates err = %v", err)
	}
	otherCand := mustBallot(EncodeBallotWithCandidates(kp.PublicKey, 3, 3, 0, 1))
	if _, err := TallyBallots([]*Ballot{withCand, otherCand}); !errors.Is(err, ErrShapeMismatch) {
		t.Errorf("candidate count mismatch err = %v", err)
	}
	if _, err := TallyBallots(nil); !errors.Is(err, ErrNoBallots) {
		t.Errorf("nil err = %v, want ErrNoBallots", err)
	}
	if _, err := TallyBallots([]*Ballot{}); !errors.Is(err, ErrNoBallots) {
		t.Errorf("empty err = %v, want ErrNoBallots", err)
	}
	if _, err := TallyBallots([]*Ballot{three, nil}); !errors.Is(err, ErrShapeMismatch) {
		t.Errorf("nil ballot err = %v, want ErrShapeMismatch", err)
	}
}

func TestBSGSUpperBound(t *testing.T) {
	kp := GenerateKeyPair()
	ct, _, err := Encrypt(kp.PublicKey, MaxDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if m := Decrypt(kp.PrivateKey, ct); m != MaxDecrypt {
		t.Fatalf("Decrypt(MaxDecrypt) = %d", m)
	}
	ct, _, err = Encrypt(kp.PublicKey, MaxDecrypt+1)
	if err != nil {
		t.Fatal(err)
	}
	if m := Decrypt(kp.PrivateKey, ct); m != -1 {
		t.Fatalf("Decrypt(MaxDecrypt+1) = %d, want -1", m)
	}
}
