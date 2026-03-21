package codes

import (
	"testing"
)

var testSecret = []byte("test-verification-secret-key-32b")

func TestGenerateCodeMapping(t *testing.T) {
	parties := []string{"ГЕРБ", "ПП-ДБ", "ДПС", "БСП"}
	mapping := GenerateCodeMapping("session-1", parties, testSecret)

	if len(mapping.Codes) != 4 {
		t.Fatalf("expected 4 codes, got %d", len(mapping.Codes))
	}
	for _, party := range parties {
		code, ok := mapping.Codes[party]
		if !ok {
			t.Fatalf("missing code for %s", party)
		}
		if len(code) != 4 {
			t.Fatalf("code should be 4 digits, got %s", code)
		}
	}
}

func TestCodeMappingDeterministic(t *testing.T) {
	parties := []string{"ГЕРБ", "ПП-ДБ"}
	m1 := GenerateCodeMapping("session-1", parties, testSecret)
	m2 := GenerateCodeMapping("session-1", parties, testSecret)

	for _, party := range parties {
		if m1.Codes[party] != m2.Codes[party] {
			t.Fatalf("same session should produce same codes for %s", party)
		}
	}
}

func TestCodeMappingDifferentSessions(t *testing.T) {
	parties := []string{"ГЕРБ"}
	m1 := GenerateCodeMapping("session-1", parties, testSecret)
	m2 := GenerateCodeMapping("session-2", parties, testSecret)

	if m1.Codes["ГЕРБ"] == m2.Codes["ГЕРБ"] {
		t.Fatal("different sessions should produce different codes (with overwhelming probability)")
	}
}

func TestDeriveReturnCode(t *testing.T) {
	code := DeriveReturnCode(testSecret, "session-1", []byte("encrypted-ballot-data"))
	if len(code) != 4 {
		t.Fatalf("return code should be 4 digits, got %s", code)
	}

	// Deterministic
	code2 := DeriveReturnCode(testSecret, "session-1", []byte("encrypted-ballot-data"))
	if code != code2 {
		t.Fatal("same input should produce same return code")
	}

	// Different ballot = different code
	code3 := DeriveReturnCode(testSecret, "session-1", []byte("different-ballot"))
	if code == code3 {
		t.Fatal("different ballot should produce different return code")
	}
}

func TestVerifyReturnCode(t *testing.T) {
	parties := []string{"ГЕРБ", "ПП-ДБ", "ДПС"}
	mapping := GenerateCodeMapping("session-1", parties, testSecret)

	// Check that each party's code maps back
	for _, party := range parties {
		code := mapping.Codes[party]
		found, ok := VerifyReturnCode(mapping, code)
		if !ok {
			t.Fatalf("code for %s should verify", party)
		}
		if found != party {
			t.Fatalf("expected %s, got %s", party, found)
		}
	}

	// Invalid code
	_, ok := VerifyReturnCode(mapping, "9999")
	if ok {
		t.Fatal("invalid code should not match any party")
	}
}
