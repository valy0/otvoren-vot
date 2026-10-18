package vectors

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/proof"
)

// TestVerifyTSProofs verifies, with the public proof.Verify* functions, the
// proofs the browser's TypeScript prover generated (testdata/ts_proofs.json,
// written by web/src/crypto/__tests__/tsFixture.test.ts with
// UPDATE_TS_FIXTURE=1). It uses the schema of vectors.json for the four proof
// sections. Every proof must also fail under Index+1.
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
	var identityAgg int
	note := func(c ContextFields) {
		if hasNonASCII(c.ElectionID) {
			nonASCII = true
		}
	}

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
		if agg := elgamal.HomomorphicAdd(cts...); bytes.Equal(agg.C1.Bytes(), make([]byte, 32)) {
			identityAgg++
			continue
		}
		ctx.Index++
		requireInvalid(t, w, proof.VerifySumOne(ctx, pk, cts, sp))
	}

	for i, cv := range v.CandidateSum {
		w := "candidate_sum_proof[" + itoa(i) + "]"
		note(cv.Context)
		pk := dElement(t, w+".pk", cv.PublicKeyHex)
		agg := dCiphertext(t, w, CiphertextFields{cv.AggC1Hex, cv.AggC2Hex})
		cp := decodeBinaryProof(t, w+".proof", cv.Proof)
		ctx := cv.Context.toContext()
		if err := proof.VerifyCandidateSum(ctx, pk, agg, cp); err != nil {
			t.Fatalf("%s: does not verify: %v", w, err)
		}
		ctx.Index++
		requireInvalid(t, w, proof.VerifyCandidateSum(ctx, pk, agg, cp))
	}

	for i, cv := range v.Consistency {
		w := "consistency_proof[" + itoa(i) + "]"
		note(cv.Context)
		pk := dElement(t, w+".pk", cv.PublicKeyHex)
		partyCt := dCiphertext(t, w+".party", cv.PartyCiphertext)
		candSumCt := dCiphertext(t, w+".cand_sum", cv.CandSumCiphertext)
		cp := decodeBinaryProof(t, w+".proof", cv.Proof)
		ctx := cv.Context.toContext()
		if err := proof.VerifyConsistency(ctx, pk, partyCt, candSumCt, cp); err != nil {
			t.Fatalf("%s: does not verify: %v", w, err)
		}
		ctx.Index++
		requireInvalid(t, w, proof.VerifyConsistency(ctx, pk, partyCt, candSumCt, cp))
	}

	if identityAgg == 0 {
		t.Fatal("no sum_one_proof with an identity aggregate c1 (the zero-randomness edge)")
	}
	if !nonASCII {
		t.Fatal("no entry has a non-ASCII election_id")
	}
	t.Logf("verified %d binary, %d sum-one, %d candidate-sum, %d consistency proofs",
		len(v.BinaryProof), len(v.SumOneProof), len(v.CandidateSum), len(v.Consistency))
}
