package jwtauth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func validClaims(sub, eid string) *SessionClaims {
	return &SessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Audience:  jwt.ClaimStrings{Audience},
			Subject:   sub,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		},
		ElectionID: eid,
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	claims := validClaims("test-session-uuid", "550e8400-e29b-41d4-a716-446655440000")

	tokenStr, err := Sign(claims, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	got, err := Verify(tokenStr, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if got.Subject != "test-session-uuid" {
		t.Errorf("Subject = %q, want %q", got.Subject, "test-session-uuid")
	}
	if got.ElectionID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("ElectionID = %q, want %q", got.ElectionID, "550e8400-e29b-41d4-a716-446655440000")
	}
	if got.Issuer != Issuer {
		t.Errorf("Issuer = %q, want %q", got.Issuer, Issuer)
	}
	if len(got.Audience) == 0 || got.Audience[0] != Audience {
		t.Errorf("Audience = %v, want [%q]", got.Audience, Audience)
	}
}

func TestVerifyExpired(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	claims := &SessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Audience:  jwt.ClaimStrings{Audience},
			Subject:   "expired-session",
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-30 * time.Minute)),
		},
		ElectionID: "election-1",
	}

	tokenStr, err := Sign(claims, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	_, err = Verify(tokenStr, pub)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	claims := validClaims("session-1", "election-1")

	tokenStr, err := Sign(claims, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	_, err = Verify(tokenStr, otherPub)
	if err == nil {
		t.Fatal("expected error for wrong key, got nil")
	}
}

func TestVerifyWrongIssuer(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	claims := &SessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "wrong-issuer",
			Audience:  jwt.ClaimStrings{Audience},
			Subject:   "session-1",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		},
		ElectionID: "election-1",
	}

	tokenStr, err := Sign(claims, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	_, err = Verify(tokenStr, pub)
	if err == nil {
		t.Fatal("expected error for wrong issuer, got nil")
	}
}

func TestVerifyWrongAudience(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	claims := &SessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Audience:  jwt.ClaimStrings{"wrong-audience"},
			Subject:   "session-1",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		},
		ElectionID: "election-1",
	}

	tokenStr, err := Sign(claims, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	_, err = Verify(tokenStr, pub)
	if err == nil {
		t.Fatal("expected error for wrong audience, got nil")
	}
}

func TestLoadKeys(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()

	// Write private key PEM.
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, "private.pem")
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	// Write public key PEM.
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "public.pem")
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	// Load and verify keys round-trip.
	loadedPriv, err := LoadEd25519PrivateKey(privPath)
	if err != nil {
		t.Fatalf("LoadEd25519PrivateKey: %v", err)
	}
	loadedPub, err := LoadEd25519PublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadEd25519PublicKey: %v", err)
	}

	// Sign with loaded private key, verify with loaded public key.
	claims := validClaims("load-test-session", "election-load")
	tokenStr, err := Sign(claims, loadedPriv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := Verify(tokenStr, loadedPub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != "load-test-session" {
		t.Errorf("Subject = %q, want %q", got.Subject, "load-test-session")
	}
}
