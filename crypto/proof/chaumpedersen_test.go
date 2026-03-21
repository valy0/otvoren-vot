package proof

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

func TestChaumPedersenValid(t *testing.T) {
	x := internal.RandomScalar()
	g := edwards25519.NewGeneratorPoint()
	h := new(edwards25519.Point).ScalarBaseMult(internal.RandomScalar())

	gx := new(edwards25519.Point).ScalarMult(x, g)
	hx := new(edwards25519.Point).ScalarMult(x, h)

	p := ProveChaumPedersen(g, h, gx, hx, x)
	if !VerifyChaumPedersen(g, h, gx, hx, p) {
		t.Fatal("valid proof should verify")
	}
}

func TestChaumPedersenMismatchedExponents(t *testing.T) {
	x := internal.RandomScalar()
	y := internal.RandomScalar()
	g := edwards25519.NewGeneratorPoint()
	h := new(edwards25519.Point).ScalarBaseMult(internal.RandomScalar())

	gx := new(edwards25519.Point).ScalarMult(x, g)
	hy := new(edwards25519.Point).ScalarMult(y, h)

	p := ProveChaumPedersen(g, h, gx, hy, x)
	if VerifyChaumPedersen(g, h, gx, hy, p) {
		t.Fatal("proof with mismatched exponents should NOT verify")
	}
}

func TestChaumPedersenTamperedProof(t *testing.T) {
	x := internal.RandomScalar()
	g := edwards25519.NewGeneratorPoint()
	h := new(edwards25519.Point).ScalarBaseMult(internal.RandomScalar())

	gx := new(edwards25519.Point).ScalarMult(x, g)
	hx := new(edwards25519.Point).ScalarMult(x, h)

	p := ProveChaumPedersen(g, h, gx, hx, x)
	// Tamper with response
	p.Z = internal.RandomScalar()
	if VerifyChaumPedersen(g, h, gx, hx, p) {
		t.Fatal("tampered proof should NOT verify")
	}
}
