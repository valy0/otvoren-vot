package proof

import (
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

func TestChaumPedersenValid(t *testing.T) {
	x := internal.RandomScalar()
	g := ristretto255.NewGeneratorElement()
	h := ristretto255.NewIdentityElement().ScalarBaseMult(internal.RandomScalar())

	gx := ristretto255.NewIdentityElement().ScalarMult(x, g)
	hx := ristretto255.NewIdentityElement().ScalarMult(x, h)

	p, err := ProveChaumPedersen(nil, g, h, gx, hx, x)
	if err != nil {
		t.Fatalf("ProveChaumPedersen: %v", err)
	}
	requireValid(t, VerifyChaumPedersen(nil, g, h, gx, hx, p), "valid proof should verify")
}

func TestChaumPedersenMismatchedExponents(t *testing.T) {
	x := internal.RandomScalar()
	y := internal.RandomScalar()
	g := ristretto255.NewGeneratorElement()
	h := ristretto255.NewIdentityElement().ScalarBaseMult(internal.RandomScalar())

	gx := ristretto255.NewIdentityElement().ScalarMult(x, g)
	hy := ristretto255.NewIdentityElement().ScalarMult(y, h)

	p, err := ProveChaumPedersen(nil, g, h, gx, hy, x)
	if err != nil {
		t.Fatalf("ProveChaumPedersen: %v", err)
	}
	requireInvalid(t, VerifyChaumPedersen(nil, g, h, gx, hy, p), "proof with mismatched exponents should NOT verify")
}

func TestChaumPedersenTamperedProof(t *testing.T) {
	x := internal.RandomScalar()
	g := ristretto255.NewGeneratorElement()
	h := ristretto255.NewIdentityElement().ScalarBaseMult(internal.RandomScalar())

	gx := ristretto255.NewIdentityElement().ScalarMult(x, g)
	hx := ristretto255.NewIdentityElement().ScalarMult(x, h)

	p, err := ProveChaumPedersen(nil, g, h, gx, hx, x)
	if err != nil {
		t.Fatalf("ProveChaumPedersen: %v", err)
	}
	// Tamper with response
	p.Z = internal.RandomScalar()
	requireInvalid(t, VerifyChaumPedersen(nil, g, h, gx, hx, p), "tampered proof should NOT verify")
}
