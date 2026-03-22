package codes

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/threshold"
)

var testParties = []string{"ГЕРБ", "ПП-ДБ", "ДПС", "БСП"}

func TestThresholdCodeGeneration(t *testing.T) {
	dealer := threshold.NewDealer(3, 5)
	secret := dealer.Secret()

	mapping := GenerateCodeMapping("session-1", testParties, secret)

	if len(mapping.Codes) != len(testParties) {
		t.Fatalf("expected %d codes, got %d", len(testParties), len(mapping.Codes))
	}
	for _, party := range testParties {
		code, ok := mapping.Codes[party]
		if !ok {
			t.Fatalf("missing code for %s", party)
		}
		if len(code) != 8 {
			t.Fatalf("code should be 8 digits, got %q", code)
		}
	}
}

func TestCodeDeterminism(t *testing.T) {
	dealer := threshold.NewDealer(3, 5)
	secret := dealer.Secret()

	m1 := GenerateCodeMapping("session-1", testParties, secret)
	m2 := GenerateCodeMapping("session-1", testParties, secret)

	for _, party := range testParties {
		if m1.Codes[party] != m2.Codes[party] {
			t.Fatalf("same session should produce same codes for %s", party)
		}
	}
}

func TestCodeVariation(t *testing.T) {
	dealer := threshold.NewDealer(3, 5)
	secret := dealer.Secret()

	m1 := GenerateCodeMapping("session-1", []string{"ГЕРБ"}, secret)
	m2 := GenerateCodeMapping("session-2", []string{"ГЕРБ"}, secret)

	if m1.Codes["ГЕРБ"] == m2.Codes["ГЕРБ"] {
		t.Fatal("different sessions should produce different codes (with overwhelming probability)")
	}
}

func TestDifferentSubsetsSameResult(t *testing.T) {
	dealer := threshold.NewDealer(3, 5)

	// Subset A: shares 1, 2, 3
	secretA := threshold.LagrangeInterpolate(
		[]*edwards25519.Scalar{dealer.Shares[0], dealer.Shares[1], dealer.Shares[2]},
		[]int{1, 2, 3},
	)
	// Subset B: shares 2, 4, 5
	secretB := threshold.LagrangeInterpolate(
		[]*edwards25519.Scalar{dealer.Shares[1], dealer.Shares[3], dealer.Shares[4]},
		[]int{2, 4, 5},
	)

	mA := GenerateCodeMapping("session-x", testParties, secretA)
	mB := GenerateCodeMapping("session-x", testParties, secretB)

	for _, party := range testParties {
		if mA.Codes[party] != mB.Codes[party] {
			t.Fatalf("different 3-of-5 subsets produced different codes for %s: %s vs %s",
				party, mA.Codes[party], mB.Codes[party])
		}
	}
}

func TestReturnCodeDerivation(t *testing.T) {
	dealer := threshold.NewDealer(3, 5)
	secret := dealer.Secret()

	code := DeriveReturnCode(secret, "session-1", []byte("encrypted-ballot-data"))
	if len(code) != 8 {
		t.Fatalf("return code should be 8 digits, got %q", code)
	}

	// Deterministic
	code2 := DeriveReturnCode(secret, "session-1", []byte("encrypted-ballot-data"))
	if code != code2 {
		t.Fatal("same input should produce same return code")
	}

	// Different ballot = different code
	code3 := DeriveReturnCode(secret, "session-1", []byte("different-ballot"))
	if code == code3 {
		t.Fatal("different ballot should produce different return code (with overwhelming probability)")
	}
}
