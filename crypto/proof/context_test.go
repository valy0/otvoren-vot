package proof

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

// The example identifiers of docs/protocol/fiat-shamir.md ("Concrete Example").
const (
	testElectionID = "избори-2027-народно-събрание"
	testBallotID   = "Zm9yLXRoZS1leGFtcGxlLW9ubHktMzItYnl0ZXMtISE"
)

// testCtx returns a ballot-proof context for statement index i.
func testCtx(i uint32) Context {
	return Context{ElectionID: testElectionID, BallotID: testBallotID, Index: i}
}

// candidateIndex is the statement index of candidate c of party p
// (docs/protocol/ballot-proofs.md section 8.4): P + 1 + Σ_{q<p} C_q + c. The
// layout reserves party slot P for the blank vote.
func candidateIndex(numParties, numCandidates, p, c int) uint32 {
	return uint32(numParties + 1 + p*numCandidates + c)
}

// mustEncrypt encrypts m under pk with randomness r.
func mustEncrypt(t *testing.T, pk *ristretto255.Element, m int, r *ristretto255.Scalar) *elgamal.Ciphertext {
	t.Helper()
	ct, err := elgamal.EncryptWithRandomness(pk, m, r)
	if err != nil {
		t.Fatalf("EncryptWithRandomness(%d): %v", m, err)
	}
	return ct
}

// requireValid fails unless err is nil.
func requireValid(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: got %v, want a valid proof", what, err)
	}
}

// requireInvalid fails unless err wraps ErrInvalidProof.
func requireInvalid(t *testing.T, err error, what string) {
	t.Helper()
	if !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("%s: got %v, want ErrInvalidProof", what, err)
	}
}

func u32be(n uint32) []byte { return binary.BigEndian.AppendUint32(nil, n) }

func TestBinaryProofBoundToContext(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	r := internal.RandomScalar()
	ct := mustEncrypt(t, kp.PublicKey, 1, r)
	ctx := testCtx(4)

	p, err := ProveBinary(ctx, kp.PublicKey, ct, 1, r)
	if err != nil {
		t.Fatalf("ProveBinary: %v", err)
	}
	requireValid(t, VerifyBinary(ctx, kp.PublicKey, ct, p), "same context")

	moved := []struct {
		name string
		ctx  Context
	}{
		{"next index", Context{ElectionID: ctx.ElectionID, BallotID: ctx.BallotID, Index: ctx.Index + 1}},
		{"other ballot", Context{ElectionID: ctx.ElectionID, BallotID: "b2", Index: ctx.Index}},
		{"other election", Context{ElectionID: "e2", BallotID: ctx.BallotID, Index: ctx.Index}},
		// Same concatenated bytes, different field boundary: the length
		// prefixes must keep these apart.
		{"shifted boundary", Context{ElectionID: ctx.ElectionID + ctx.BallotID[:1], BallotID: ctx.BallotID[1:], Index: ctx.Index}},
	}
	for _, tc := range moved {
		t.Run(tc.name, func(t *testing.T) {
			requireInvalid(t, VerifyBinary(tc.ctx, kp.PublicKey, ct, p), tc.name)
		})
	}
}

func TestSlotSwapFailsVerification(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	const numParties = 3
	ballot, err := elgamal.EncodeBallot(kp.PublicKey, numParties, 0) // vote for party 0
	if err != nil {
		t.Fatalf("EncodeBallot: %v", err)
	}

	proofs := make([]*BinaryProof, numParties)
	for i := range numParties {
		m := 0
		if i == 0 {
			m = 1
		}
		proofs[i], err = ProveBinary(testCtx(uint32(i)), kp.PublicKey, ballot.PartyVector[i], m, ballot.PartyRandomness[i])
		if err != nil {
			t.Fatalf("ProveBinary slot %d: %v", i, err)
		}
		requireValid(t, VerifyBinary(testCtx(uint32(i)), kp.PublicKey, ballot.PartyVector[i], proofs[i]), fmt.Sprintf("slot %d before swap", i))
	}
	rSum := internal.SumScalars(ballot.PartyRandomness)
	sumProof, err := ProveSumOne(testCtx(0), kp.PublicKey, ballot.PartyVector, rSum)
	if err != nil {
		t.Fatalf("ProveSumOne: %v", err)
	}

	// Swap slots 0 and 2, each ciphertext with its proof. This moves the
	// vote from party 0 to party 2.
	cts := slices.Clone(ballot.PartyVector)
	cts[0], cts[2] = cts[2], cts[0]
	proofs[0], proofs[2] = proofs[2], proofs[0]

	// The aggregate is unchanged, so the sum proof cannot see the swap; the
	// binary proofs' index is what catches it.
	requireValid(t, VerifySumOne(testCtx(0), kp.PublicKey, cts, sumProof), "sum proof over swapped vector")

	for _, i := range []int{0, 2} {
		requireInvalid(t, VerifyBinary(testCtx(uint32(i)), kp.PublicKey, cts[i], proofs[i]), fmt.Sprintf("slot %d after swap", i))
	}
}

func TestSumProofBoundToBallotID(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	ballot, err := elgamal.EncodeBallot(kp.PublicKey, 4, 1)
	if err != nil {
		t.Fatalf("EncodeBallot: %v", err)
	}
	rSum := internal.SumScalars(ballot.PartyRandomness)
	ctx := testCtx(0)

	p, err := ProveSumOne(ctx, kp.PublicKey, ballot.PartyVector, rSum)
	if err != nil {
		t.Fatalf("ProveSumOne: %v", err)
	}
	requireValid(t, VerifySumOne(ctx, kp.PublicKey, ballot.PartyVector, p), "same context")

	otherBallot := ctx
	otherBallot.BallotID = "b2"
	requireInvalid(t, VerifySumOne(otherBallot, kp.PublicKey, ballot.PartyVector, p), "other ballot")

	otherElection := ctx
	otherElection.ElectionID = "e2"
	requireInvalid(t, VerifySumOne(otherElection, kp.PublicKey, ballot.PartyVector, p), "other election")
}

func TestCandidateProofsBoundToPartyIndex(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	ballot, err := elgamal.EncodeBallotWithCandidates(kp.PublicKey, 3, 2, 1, 0) // party 1, candidate 0
	if err != nil {
		t.Fatalf("EncodeBallotWithCandidates: %v", err)
	}
	const party = 1
	aggCt := elgamal.HomomorphicAdd(ballot.CandidateVectors[party]...)
	rCandSum := internal.SumScalars(ballot.CandRandomness[party])

	cs, err := ProveCandidateSum(testCtx(party), kp.PublicKey, aggCt, 1, rCandSum)
	if err != nil {
		t.Fatalf("ProveCandidateSum: %v", err)
	}
	requireValid(t, VerifyCandidateSum(testCtx(party), kp.PublicKey, aggCt, cs), "candidate-sum at its index")
	requireInvalid(t, VerifyCandidateSum(testCtx(party+1), kp.PublicKey, aggCt, cs), "candidate-sum at index 2")

	rDiff := ristretto255.NewScalar().Subtract(ballot.PartyRandomness[party], rCandSum)
	con, err := ProveConsistency(testCtx(party), kp.PublicKey, ballot.PartyVector[party], aggCt, 0, rDiff)
	if err != nil {
		t.Fatalf("ProveConsistency: %v", err)
	}
	requireValid(t, VerifyConsistency(testCtx(party), kp.PublicKey, ballot.PartyVector[party], aggCt, con), "consistency at its index")
	requireInvalid(t, VerifyConsistency(testCtx(party+1), kp.PublicKey, ballot.PartyVector[party], aggCt, con), "consistency at index 2")
}

func TestChaumPedersenBindsContext(t *testing.T) {
	x := internal.RandomScalar()
	g := ristretto255.NewGeneratorElement()
	h := ristretto255.NewIdentityElement().ScalarBaseMult(internal.RandomScalar())
	A := ristretto255.NewIdentityElement().ScalarMult(x, g)
	B := ristretto255.NewIdentityElement().ScalarMult(x, h)

	p, err := ProveChaumPedersen([][]byte{[]byte("a")}, g, h, A, B, x)
	if err != nil {
		t.Fatalf("ProveChaumPedersen: %v", err)
	}
	requireValid(t, VerifyChaumPedersen([][]byte{[]byte("a")}, g, h, A, B, p), "same context")
	requireInvalid(t, VerifyChaumPedersen([][]byte{[]byte("b")}, g, h, A, B, p), "other context")
	requireInvalid(t, VerifyChaumPedersen(nil, g, h, A, B, p), "no context")

	// Each context slice gets its own length prefix.
	split, err := ProveChaumPedersen([][]byte{[]byte("a"), []byte("b")}, g, h, A, B, x)
	if err != nil {
		t.Fatalf("ProveChaumPedersen: %v", err)
	}
	requireValid(t, VerifyChaumPedersen([][]byte{[]byte("a"), []byte("b")}, g, h, A, B, split), "split context")
	requireInvalid(t, VerifyChaumPedersen([][]byte{[]byte("ab")}, g, h, A, B, split), "joined context")
}

// TestTranscriptsFollowSpec recomputes every challenge field by field from
// docs/protocol/fiat-shamir.md, independently of the package's transcript
// helpers, so a reordered or dropped field fails here even though prover and
// verifier would still agree with each other.
func TestTranscriptsFollowSpec(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	pk := kp.PublicKey
	g := ristretto255.NewGeneratorElement()
	ctx := testCtx(7)
	head := [][]byte{[]byte(ctx.ElectionID), []byte(ctx.BallotID), u32be(ctx.Index)}

	// binaryShaped checks e0 + e1 against FiatShamir(domain, election_id,
	// ballot_id, index, pk, C1, C2, A0, B0, A1, B1).
	binaryShaped := func(t *testing.T, domain string, ct *elgamal.Ciphertext, p *BinaryProof) {
		t.Helper()
		fields := append(slices.Clone(head),
			pk.Bytes(), ct.C1.Bytes(), ct.C2.Bytes(),
			p.A0.Bytes(), p.B0.Bytes(), p.A1.Bytes(), p.B1.Bytes())
		want := internal.FiatShamir(domain, fields...)
		if ristretto255.NewScalar().Add(p.E0, p.E1).Equal(want) != 1 {
			t.Fatalf("%s: challenge does not match the fiat-shamir.md transcript", domain)
		}
	}

	r := internal.RandomScalar()
	ct := mustEncrypt(t, pk, 1, r)

	t.Run("binary", func(t *testing.T) {
		p, err := ProveBinary(ctx, pk, ct, 1, r)
		if err != nil {
			t.Fatal(err)
		}
		binaryShaped(t, "otvoren-vot.ballot-binary-proof", ct, p)
	})

	t.Run("candidate-sum", func(t *testing.T) {
		p, err := ProveCandidateSum(ctx, pk, ct, 1, r)
		if err != nil {
			t.Fatal(err)
		}
		binaryShaped(t, "otvoren-vot.candidate-sum-01-proof", ct, p)
	})

	t.Run("consistency", func(t *testing.T) {
		rCand := internal.RandomScalar()
		candCt := mustEncrypt(t, pk, 1, rCand)
		rDiff := ristretto255.NewScalar().Subtract(r, rCand)
		p, err := ProveConsistency(ctx, pk, ct, candCt, 0, rDiff)
		if err != nil {
			t.Fatal(err)
		}
		diffCt := &elgamal.Ciphertext{
			C1: ristretto255.NewIdentityElement().Subtract(ct.C1, candCt.C1),
			C2: ristretto255.NewIdentityElement().Subtract(ct.C2, candCt.C2),
		}
		binaryShaped(t, "otvoren-vot.candidate-consistency-proof", diffCt, p)
	})

	t.Run("sum", func(t *testing.T) {
		r0, r1 := internal.RandomScalar(), internal.RandomScalar()
		cts := []*elgamal.Ciphertext{mustEncrypt(t, pk, 0, r0), mustEncrypt(t, pk, 1, r1)}
		p, err := ProveSumOne(ctx, pk, cts, ristretto255.NewScalar().Add(r0, r1))
		if err != nil {
			t.Fatal(err)
		}
		agg := elgamal.HomomorphicAdd(cts...)
		fields := append(slices.Clone(head), pk.Bytes(), agg.C1.Bytes(), agg.C2.Bytes(), p.A.Bytes(), p.B.Bytes())
		e := internal.FiatShamir("otvoren-vot.ballot-sum-proof", fields...)
		// z*G == A + e*C1_agg holds only for the challenge the prover used.
		lhs := ristretto255.NewIdentityElement().ScalarBaseMult(p.Z)
		rhs := ristretto255.NewIdentityElement().ScalarMult(e, agg.C1)
		rhs.Add(p.A, rhs)
		if lhs.Equal(rhs) != 1 {
			t.Fatal("sum: challenge does not match the fiat-shamir.md transcript")
		}
	})

	t.Run("chaum-pedersen", func(t *testing.T) {
		// The partial-decryption shape: context fields, then (G, c1, h_i, d_i, u, v).
		x := internal.RandomScalar()
		hi := ristretto255.NewIdentityElement().ScalarBaseMult(x)
		di := ristretto255.NewIdentityElement().ScalarMult(x, ct.C1)
		context := [][]byte{[]byte(ctx.ElectionID), u32be(2), u32be(5), ct.C2.Bytes()}
		p, err := ProveChaumPedersen(context, g, ct.C1, hi, di, x)
		if err != nil {
			t.Fatal(err)
		}
		fields := append(slices.Clone(context), g.Bytes(), ct.C1.Bytes(), hi.Bytes(), di.Bytes(), p.U.Bytes(), p.V.Bytes())
		e := internal.FiatShamir("otvoren-vot.chaum-pedersen", fields...)
		// z*G == u + e*h_i holds only for the challenge the prover used.
		lhs := ristretto255.NewIdentityElement().ScalarBaseMult(p.Z)
		rhs := ristretto255.NewIdentityElement().ScalarMult(e, hi)
		rhs.Add(p.U, rhs)
		if lhs.Equal(rhs) != 1 {
			t.Fatal("chaum-pedersen: challenge does not match the fiat-shamir.md transcript")
		}
	})
}
