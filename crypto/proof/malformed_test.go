package proof

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

// mustNotPanic runs f and turns a panic into a test failure.
func mustNotPanic(t *testing.T, f func() error) error {
	t.Helper()
	var (
		err      error
		panicked any
	)
	func() {
		defer func() { panicked = recover() }()
		err = f()
	}()
	if panicked != nil {
		t.Fatalf("panicked: %v", panicked)
	}
	return err
}

type malformedCase struct {
	name string
	call func() error
}

func runMalformed(t *testing.T, cases []malformedCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := mustNotPanic(t, tc.call); !errors.Is(err, ErrMalformed) {
				t.Fatalf("got %v, want ErrMalformed", err)
			}
		})
	}
}

// errOf adapts a prover call to runMalformed. A proof returned alongside an
// error becomes an error that does not wrap ErrMalformed, so the case fails.
func errOf[P any](p *P, err error) error {
	if err != nil && p != nil {
		return fmt.Errorf("proof returned alongside error %q", err)
	}
	return err
}

func TestVerifiersRejectMalformedWithoutPanic(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	pk := kp.PublicKey
	identity := ristretto255.NewIdentityElement()
	ctx := testCtx(0)
	noElection := Context{BallotID: testBallotID}
	noBallot := Context{ElectionID: testElectionID}

	r := internal.RandomScalar()
	ct := mustEncrypt(t, pk, 1, r)
	nilC1 := &elgamal.Ciphertext{C2: ct.C2}
	nilC2 := &elgamal.Ciphertext{C1: ct.C1}

	bp, err := ProveBinary(ctx, pk, ct, 1, r)
	if err != nil {
		t.Fatalf("ProveBinary: %v", err)
	}
	withoutBinary := func(clear func(*BinaryProof)) *BinaryProof {
		c := *bp
		clear(&c)
		return &c
	}

	cts := []*elgamal.Ciphertext{ct}
	sp, err := ProveSumOne(ctx, pk, cts, r)
	if err != nil {
		t.Fatalf("ProveSumOne: %v", err)
	}
	withoutSum := func(clear func(*SumOneProof)) *SumOneProof {
		c := *sp
		clear(&c)
		return &c
	}

	x := internal.RandomScalar()
	g := ristretto255.NewGeneratorElement()
	h := ristretto255.NewIdentityElement().ScalarBaseMult(internal.RandomScalar())
	A := ristretto255.NewIdentityElement().ScalarMult(x, g)
	B := ristretto255.NewIdentityElement().ScalarMult(x, h)
	cp, err := ProveChaumPedersen(nil, g, h, A, B, x)
	if err != nil {
		t.Fatalf("ProveChaumPedersen: %v", err)
	}
	withoutCP := func(clear func(*ChaumPedersenProof)) *ChaumPedersenProof {
		c := *cp
		clear(&c)
		return &c
	}

	runMalformed(t, []malformedCase{
		// VerifyBinary
		{"binary nil proof", func() error { return VerifyBinary(ctx, pk, ct, nil) }},
		{"binary nil A0", func() error { return VerifyBinary(ctx, pk, ct, withoutBinary(func(p *BinaryProof) { p.A0 = nil })) }},
		{"binary nil A1", func() error { return VerifyBinary(ctx, pk, ct, withoutBinary(func(p *BinaryProof) { p.A1 = nil })) }},
		{"binary nil B0", func() error { return VerifyBinary(ctx, pk, ct, withoutBinary(func(p *BinaryProof) { p.B0 = nil })) }},
		{"binary nil B1", func() error { return VerifyBinary(ctx, pk, ct, withoutBinary(func(p *BinaryProof) { p.B1 = nil })) }},
		{"binary nil E0", func() error { return VerifyBinary(ctx, pk, ct, withoutBinary(func(p *BinaryProof) { p.E0 = nil })) }},
		{"binary nil E1", func() error { return VerifyBinary(ctx, pk, ct, withoutBinary(func(p *BinaryProof) { p.E1 = nil })) }},
		{"binary nil Z0", func() error { return VerifyBinary(ctx, pk, ct, withoutBinary(func(p *BinaryProof) { p.Z0 = nil })) }},
		{"binary nil Z1", func() error { return VerifyBinary(ctx, pk, ct, withoutBinary(func(p *BinaryProof) { p.Z1 = nil })) }},
		{"binary nil ct", func() error { return VerifyBinary(ctx, pk, nil, bp) }},
		{"binary nil ct.C1", func() error { return VerifyBinary(ctx, pk, nilC1, bp) }},
		{"binary nil ct.C2", func() error { return VerifyBinary(ctx, pk, nilC2, bp) }},
		{"binary nil pk", func() error { return VerifyBinary(ctx, nil, ct, bp) }},
		{"binary identity pk", func() error { return VerifyBinary(ctx, identity, ct, bp) }},
		{"binary empty ElectionID", func() error { return VerifyBinary(noElection, pk, ct, bp) }},
		{"binary empty BallotID", func() error { return VerifyBinary(noBallot, pk, ct, bp) }},

		// VerifySumOne
		{"sum empty cts", func() error { return VerifySumOne(ctx, pk, []*elgamal.Ciphertext{}, sp) }},
		{"sum nil cts", func() error { return VerifySumOne(ctx, pk, nil, sp) }},
		{"sum nil element", func() error { return VerifySumOne(ctx, pk, []*elgamal.Ciphertext{ct, nil}, sp) }},
		{"sum element with nil C1", func() error { return VerifySumOne(ctx, pk, []*elgamal.Ciphertext{ct, nilC1}, sp) }},
		{"sum element with nil C2", func() error { return VerifySumOne(ctx, pk, []*elgamal.Ciphertext{nilC2, ct}, sp) }},
		{"sum nil proof", func() error { return VerifySumOne(ctx, pk, cts, nil) }},
		{"sum nil A", func() error { return VerifySumOne(ctx, pk, cts, withoutSum(func(p *SumOneProof) { p.A = nil })) }},
		{"sum nil B", func() error { return VerifySumOne(ctx, pk, cts, withoutSum(func(p *SumOneProof) { p.B = nil })) }},
		{"sum nil Z", func() error { return VerifySumOne(ctx, pk, cts, withoutSum(func(p *SumOneProof) { p.Z = nil })) }},
		{"sum identity pk", func() error { return VerifySumOne(ctx, identity, cts, sp) }},
		{"sum empty ElectionID", func() error { return VerifySumOne(noElection, pk, cts, sp) }},
		{"sum empty BallotID", func() error { return VerifySumOne(noBallot, pk, cts, sp) }},

		// VerifyCandidateSum
		{"candidate-sum nil aggCt", func() error { return VerifyCandidateSum(ctx, pk, nil, bp) }},
		{"candidate-sum nil aggCt.C1", func() error { return VerifyCandidateSum(ctx, pk, nilC1, bp) }},
		{"candidate-sum nil proof", func() error { return VerifyCandidateSum(ctx, pk, ct, nil) }},
		{"candidate-sum nil Z1", func() error {
			return VerifyCandidateSum(ctx, pk, ct, withoutBinary(func(p *BinaryProof) { p.Z1 = nil }))
		}},
		{"candidate-sum identity pk", func() error { return VerifyCandidateSum(ctx, identity, ct, bp) }},
		{"candidate-sum empty BallotID", func() error { return VerifyCandidateSum(noBallot, pk, ct, bp) }},

		// VerifyConsistency
		{"consistency nil partyCt", func() error { return VerifyConsistency(ctx, pk, nil, ct, bp) }},
		{"consistency nil candSumCt", func() error { return VerifyConsistency(ctx, pk, ct, nil, bp) }},
		{"consistency partyCt nil C1", func() error { return VerifyConsistency(ctx, pk, nilC1, ct, bp) }},
		{"consistency candSumCt nil C2", func() error { return VerifyConsistency(ctx, pk, ct, nilC2, bp) }},
		{"consistency nil proof", func() error { return VerifyConsistency(ctx, pk, ct, ct, nil) }},
		{"consistency nil E0", func() error {
			return VerifyConsistency(ctx, pk, ct, ct, withoutBinary(func(p *BinaryProof) { p.E0 = nil }))
		}},
		{"consistency nil pk", func() error { return VerifyConsistency(ctx, nil, ct, ct, bp) }},
		{"consistency identity pk", func() error { return VerifyConsistency(ctx, identity, ct, ct, bp) }},
		{"consistency empty ElectionID", func() error { return VerifyConsistency(noElection, pk, ct, ct, bp) }},

		// VerifyChaumPedersen
		{"chaum-pedersen nil proof", func() error { return VerifyChaumPedersen(nil, g, h, A, B, nil) }},
		{"chaum-pedersen nil U", func() error {
			return VerifyChaumPedersen(nil, g, h, A, B, withoutCP(func(p *ChaumPedersenProof) { p.U = nil }))
		}},
		{"chaum-pedersen nil V", func() error {
			return VerifyChaumPedersen(nil, g, h, A, B, withoutCP(func(p *ChaumPedersenProof) { p.V = nil }))
		}},
		{"chaum-pedersen nil Z", func() error {
			return VerifyChaumPedersen(nil, g, h, A, B, withoutCP(func(p *ChaumPedersenProof) { p.Z = nil }))
		}},
		{"chaum-pedersen nil g", func() error { return VerifyChaumPedersen(nil, nil, h, A, B, cp) }},
		{"chaum-pedersen nil h", func() error { return VerifyChaumPedersen(nil, g, nil, A, B, cp) }},
		{"chaum-pedersen nil A", func() error { return VerifyChaumPedersen(nil, g, h, nil, B, cp) }},
		{"chaum-pedersen nil B", func() error { return VerifyChaumPedersen(nil, g, h, A, nil, cp) }},
	})
}

func TestProveRejectsNonBit(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	pk := kp.PublicKey
	ctx := testCtx(0)
	r := internal.RandomScalar()
	ct := mustEncrypt(t, pk, 1, r)
	rCand := internal.RandomScalar()
	candCt := mustEncrypt(t, pk, 1, rCand)
	rDiff := ristretto255.NewScalar().Subtract(r, rCand)

	cases := []struct {
		name  string
		prove func() (*BinaryProof, error)
	}{
		{"ProveBinary m=2", func() (*BinaryProof, error) { return ProveBinary(ctx, pk, ct, 2, r) }},
		{"ProveBinary m=-1", func() (*BinaryProof, error) { return ProveBinary(ctx, pk, ct, -1, r) }},
		{"ProveCandidateSum sum=2", func() (*BinaryProof, error) { return ProveCandidateSum(ctx, pk, ct, 2, r) }},
		{"ProveConsistency diff=-1", func() (*BinaryProof, error) { return ProveConsistency(ctx, pk, ct, candCt, -1, rDiff) }},
		{"ProveConsistency diff=2", func() (*BinaryProof, error) { return ProveConsistency(ctx, pk, ct, candCt, 2, rDiff) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := tc.prove()
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("got %v, want ErrMalformed", err)
			}
			if p != nil {
				t.Fatal("got a proof alongside the error")
			}
		})
	}
}

func TestProversRejectMalformedWithoutPanic(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	pk := kp.PublicKey
	identity := ristretto255.NewIdentityElement()
	ctx := testCtx(0)
	noElection := Context{BallotID: testBallotID}
	noBallot := Context{ElectionID: testElectionID}

	r := internal.RandomScalar()
	ct := mustEncrypt(t, pk, 1, r)
	nilC1 := &elgamal.Ciphertext{C2: ct.C2}
	cts := []*elgamal.Ciphertext{ct}

	x := internal.RandomScalar()
	g := ristretto255.NewGeneratorElement()
	h := ristretto255.NewIdentityElement().ScalarBaseMult(internal.RandomScalar())
	A := ristretto255.NewIdentityElement().ScalarMult(x, g)
	B := ristretto255.NewIdentityElement().ScalarMult(x, h)

	runMalformed(t, []malformedCase{
		{"binary empty ElectionID", func() error { return errOf(ProveBinary(noElection, pk, ct, 1, r)) }},
		{"binary empty BallotID", func() error { return errOf(ProveBinary(noBallot, pk, ct, 1, r)) }},
		{"binary nil pk", func() error { return errOf(ProveBinary(ctx, nil, ct, 1, r)) }},
		{"binary identity pk", func() error { return errOf(ProveBinary(ctx, identity, ct, 1, r)) }},
		{"binary nil ct", func() error { return errOf(ProveBinary(ctx, pk, nil, 1, r)) }},
		{"binary nil ct.C1", func() error { return errOf(ProveBinary(ctx, pk, nilC1, 1, r)) }},
		{"binary nil r", func() error { return errOf(ProveBinary(ctx, pk, ct, 1, nil)) }},

		{"sum empty cts", func() error { return errOf(ProveSumOne(ctx, pk, nil, r)) }},
		{"sum nil element", func() error { return errOf(ProveSumOne(ctx, pk, []*elgamal.Ciphertext{ct, nil}, r)) }},
		{"sum element with nil C1", func() error { return errOf(ProveSumOne(ctx, pk, []*elgamal.Ciphertext{nilC1}, r)) }},
		{"sum nil rSum", func() error { return errOf(ProveSumOne(ctx, pk, cts, nil)) }},
		{"sum identity pk", func() error { return errOf(ProveSumOne(ctx, identity, cts, r)) }},
		{"sum empty BallotID", func() error { return errOf(ProveSumOne(noBallot, pk, cts, r)) }},

		{"candidate-sum nil aggCt", func() error { return errOf(ProveCandidateSum(ctx, pk, nil, 1, r)) }},
		{"candidate-sum nil rSum", func() error { return errOf(ProveCandidateSum(ctx, pk, ct, 1, nil)) }},
		{"candidate-sum empty ElectionID", func() error { return errOf(ProveCandidateSum(noElection, pk, ct, 1, r)) }},

		{"consistency nil partyCt", func() error { return errOf(ProveConsistency(ctx, pk, nil, ct, 0, r)) }},
		{"consistency nil candSumCt", func() error { return errOf(ProveConsistency(ctx, pk, ct, nil, 0, r)) }},
		{"consistency candSumCt nil C1", func() error { return errOf(ProveConsistency(ctx, pk, ct, nilC1, 0, r)) }},
		{"consistency nil rDiff", func() error { return errOf(ProveConsistency(ctx, pk, ct, ct, 0, nil)) }},
		{"consistency identity pk", func() error { return errOf(ProveConsistency(ctx, identity, ct, ct, 0, r)) }},
		{"consistency empty BallotID", func() error { return errOf(ProveConsistency(noBallot, pk, ct, ct, 0, r)) }},

		{"chaum-pedersen nil g", func() error { return errOf(ProveChaumPedersen(nil, nil, h, A, B, x)) }},
		{"chaum-pedersen nil h", func() error { return errOf(ProveChaumPedersen(nil, g, nil, A, B, x)) }},
		{"chaum-pedersen nil A", func() error { return errOf(ProveChaumPedersen(nil, g, h, nil, B, x)) }},
		{"chaum-pedersen nil B", func() error { return errOf(ProveChaumPedersen(nil, g, h, A, nil, x)) }},
		{"chaum-pedersen nil x", func() error { return errOf(ProveChaumPedersen(nil, g, h, A, B, nil)) }},
	})
}
