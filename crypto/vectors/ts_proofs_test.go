package vectors

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/group"
	"github.com/valy0/otvoren-vot/crypto/proof"
)

// TestVerifyTSProofs verifies, with the public proof.Verify* functions, the
// proofs the browser's TypeScript prover generated (testdata/ts_proofs.json,
// written by web/src/crypto/__tests__/tsFixture.test.ts with
// UPDATE_TS_FIXTURE=1). It uses the schema of vectors.json for the four proof
// sections. Every proof must also fail under Index+1, except exactly one
// sum-one proof whose aggregate is (identity, g).
//
// Wire fields are decoded with group.DecodeElement and
// elgamal.CiphertextFromBytes. The candidate-sum aggregate and the
// consistency cand_sum_ciphertext are homomorphic sums the verifier derives,
// so they are decoded with dAggregate, which allows the identity.
func TestVerifyTSProofs(t *testing.T) {
	data, err := os.ReadFile("testdata/ts_proofs.json")
	if err != nil {
		t.Fatal("testdata/ts_proofs.json not found; run: cd web && UPDATE_TS_FIXTURE=1 npx vitest run src/crypto/__tests__/tsFixture.test.ts")
	}
	var v Vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal("failed to unmarshal ts_proofs.json:", err)
	}

	for name, n := range map[string]int{
		"binary_proof": len(v.BinaryProof), "sum_one_proof": len(v.SumOneProof),
		"candidate_sum_proof": len(v.CandidateSum), "consistency_proof": len(v.Consistency),
	} {
		if n == 0 {
			t.Fatalf("section %s is empty", name)
		}
	}

	var nonASCII bool
	note := func(c ContextFields) {
		if hasNonASCII(c.ElectionID) {
			nonASCII = true
		}
	}
	// The identity edges the fixture must keep.
	var identitySumOne, identityCandSum int
	identityAggSums := map[int]bool{} // candidate_sum_proof: sum values with an identity aggregate c1
	identityDiffs := map[int]bool{}   // consistency_proof: diff values with an identity difference c1

	for i, bv := range v.BinaryProof {
		w := "binary_proof[" + itoa(i) + "]"
		note(bv.Context)
		pk := dElement(t, w+".pk", bv.PublicKeyHex)
		ct := dCiphertext(t, w, CiphertextFields{bv.CiphertextC1, bv.CiphertextC2})
		bp := decodeBinaryProof(t, w+".proof", bv.Proof)
		ctx := bv.Context.toContext()
		if err := proof.VerifyBinary(ctx, pk, ct, bp); err != nil {
			t.Fatalf("%s: does not verify: %v", w, err)
		}
		ctx.Index++
		requireInvalid(t, w, proof.VerifyBinary(ctx, pk, ct, bp))
	}

	for i, sv := range v.SumOneProof {
		w := "sum_one_proof[" + itoa(i) + "]"
		note(sv.Context)
		pk := dElement(t, w+".pk", sv.PublicKeyHex)
		cts := make([]*elgamal.Ciphertext, len(sv.Ciphertexts))
		for j, c := range sv.Ciphertexts {
			cts[j] = dCiphertext(t, w+".ct["+itoa(j)+"]", c)
		}
		sp := &proof.SumOneProof{
			A: dElement(t, w+".a", sv.Proof.AHex),
			B: dElement(t, w+".b", sv.Proof.BHex),
			Z: dScalar(t, w+".z", sv.Proof.ZHex),
		}
		ctx := sv.Context.toContext()
		if err := proof.VerifySumOne(ctx, pk, cts, sp); err != nil {
			t.Fatalf("%s: does not verify: %v", w, err)
		}
		// A zero randomness sum makes the aggregate exactly (identity, g): both
		// verification equations then lose their dependence on the challenge, so
		// the proof verifies under any context. Every other proof must fail.
		if isIdentity(elgamal.HomomorphicAdd(cts...).C1) {
			identitySumOne++
			continue
		}
		ctx.Index++
		requireInvalid(t, w, proof.VerifySumOne(ctx, pk, cts, sp))
	}

	for i, cv := range v.CandidateSum {
		w := "candidate_sum_proof[" + itoa(i) + "]"
		note(cv.Context)
		pk := dElement(t, w+".pk", cv.PublicKeyHex)
		agg := dAggregate(t, w+".agg", CiphertextFields{cv.AggC1Hex, cv.AggC2Hex})
		cp := decodeBinaryProof(t, w+".proof", cv.Proof)
		ctx := cv.Context.toContext()
		if err := proof.VerifyCandidateSum(ctx, pk, agg, cp); err != nil {
			t.Fatalf("%s: does not verify: %v", w, err)
		}
		if isIdentity(agg.C1) {
			identityAggSums[cv.Sum] = true
		}
		// Identity aggregates included: the challenge split e0 + e1 = e binds them.
		ctx.Index++
		requireInvalid(t, w, proof.VerifyCandidateSum(ctx, pk, agg, cp))
	}

	for i, cv := range v.Consistency {
		w := "consistency_proof[" + itoa(i) + "]"
		note(cv.Context)
		pk := dElement(t, w+".pk", cv.PublicKeyHex)
		partyCt := dCiphertext(t, w+".party", cv.PartyCiphertext)
		candSumCt := dAggregate(t, w+".cand_sum", cv.CandSumCiphertext)
		cp := decodeBinaryProof(t, w+".proof", cv.Proof)
		ctx := cv.Context.toContext()
		if err := proof.VerifyConsistency(ctx, pk, partyCt, candSumCt, cp); err != nil {
			t.Fatalf("%s: does not verify: %v", w, err)
		}
		if isIdentity(candSumCt.C1) {
			identityCandSum++
		}
		if isIdentity(ristretto255.NewIdentityElement().Subtract(partyCt.C1, candSumCt.C1)) {
			identityDiffs[cv.Diff] = true
		}
		ctx.Index++
		requireInvalid(t, w, proof.VerifyConsistency(ctx, pk, partyCt, candSumCt, cp))
	}

	// Exactly one context-free entry: a second one must not slip through the
	// Index+1 check unnoticed.
	if identitySumOne != 1 {
		t.Fatalf("want exactly 1 sum_one_proof with an identity aggregate c1 (the zero-randomness edge), got %d", identitySumOne)
	}
	if !identityAggSums[0] || !identityAggSums[1] {
		t.Fatalf("candidate_sum_proof: want an identity aggregate c1 for sum 0 and sum 1, got %v", identityAggSums)
	}
	if identityCandSum == 0 {
		t.Fatal("consistency_proof: no entry whose cand_sum_ciphertext c1 is the identity (R_cand = 0)")
	}
	if !identityDiffs[0] || !identityDiffs[1] {
		t.Fatalf("consistency_proof: want r_party = R_cand (identity difference c1) for diff 0 and diff 1, got %v", identityDiffs)
	}
	if !nonASCII {
		t.Fatal("no entry has a non-ASCII election_id")
	}
	t.Logf("verified %d binary, %d sum-one, %d candidate-sum, %d consistency proofs",
		len(v.BinaryProof), len(v.SumOneProof), len(v.CandidateSum), len(v.Consistency))
}

func isIdentity(e *ristretto255.Element) bool {
	return e.Equal(ristretto255.NewIdentityElement()) == 1
}

// dAggregate decodes a ciphertext the verifier derives as a homomorphic sum
// (agg_c1_hex/agg_c2_hex, cand_sum_ciphertext). Unlike
// elgamal.CiphertextFromBytes it allows the identity in either half:
// randomness that sums to 0 mod l makes c1 the identity, and c2 too when the
// plaintext sum is 0. Never use it for a wire field.
func dAggregate(t *testing.T, where string, c CiphertextFields) *elgamal.Ciphertext {
	t.Helper()
	return &elgamal.Ciphertext{
		C1: dElementOrIdentity(t, where+".c1", c.C1Hex),
		C2: dElementOrIdentity(t, where+".c2", c.C2Hex),
	}
}

// dElementOrIdentity decodes exactly 32 bytes as a canonical element, the
// identity included.
func dElementOrIdentity(t *testing.T, where, h string) *ristretto255.Element {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("%s: bad hex: %v", where, err)
	}
	if len(b) != group.ElementSize {
		t.Fatalf("%s: element has %d bytes, want %d", where, len(b), group.ElementSize)
	}
	e, err := ristretto255.NewIdentityElement().SetCanonicalBytes(b)
	if err != nil {
		t.Fatalf("%s: non-canonical element: %v", where, err)
	}
	return e
}
