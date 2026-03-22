package testdata

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
	"github.com/valy0/otvoren-vot/crypto/proof"
)

// Vectors is the top-level test vector structure for cross-language interop.
type Vectors struct {
	ScalarBaseMult []ScalarBaseMultVector `json:"scalar_base_mult"`
	ElGamalEncrypt []ElGamalEncryptVector `json:"elgamal_encrypt"`
	FiatShamir     []FiatShamirVector     `json:"fiat_shamir"`
	BinaryProof    []BinaryProofVector    `json:"binary_proof"`
	CandidateSum   []CandidateSumVector   `json:"candidate_sum_proof"`
	Consistency    []ConsistencyVector    `json:"consistency_proof"`
}

type ScalarBaseMultVector struct {
	ScalarHex        string `json:"scalar_hex"`
	ExpectedPointHex string `json:"expected_point_hex"`
}

type ElGamalEncryptVector struct {
	PublicKeyHex   string `json:"public_key_hex"`
	RandomnessHex  string `json:"randomness_hex"`
	Message        int    `json:"message"`
	ExpectedC1Hex  string `json:"expected_c1_hex"`
	ExpectedC2Hex  string `json:"expected_c2_hex"`
}

type FiatShamirVector struct {
	Domain            string   `json:"domain"`
	DataHex           []string `json:"data_hex"`
	ExpectedScalarHex string   `json:"expected_scalar_hex"`
}

type BinaryProofFields struct {
	A0Hex string `json:"a0_hex"`
	B0Hex string `json:"b0_hex"`
	A1Hex string `json:"a1_hex"`
	B1Hex string `json:"b1_hex"`
	E0Hex string `json:"e0_hex"`
	E1Hex string `json:"e1_hex"`
	Z0Hex string `json:"z0_hex"`
	Z1Hex string `json:"z1_hex"`
}

type BinaryProofVector struct {
	Domain         string            `json:"domain"`
	PublicKeyHex   string            `json:"public_key_hex"`
	RandomnessHex  string            `json:"randomness_hex"`
	Message        int               `json:"message"`
	CiphertextC1   string            `json:"ciphertext_c1_hex"`
	CiphertextC2   string            `json:"ciphertext_c2_hex"`
	ExpectedProof  BinaryProofFields `json:"expected_proof"`
}

type CandidateSumVector struct {
	PublicKeyHex    string            `json:"public_key_hex"`
	CandRandomHexes []string          `json:"cand_randomness_hexes"`
	CandMessages    []int             `json:"cand_messages"`
	AggC1Hex        string            `json:"agg_c1_hex"`
	AggC2Hex        string            `json:"agg_c2_hex"`
	Sum             int               `json:"sum"`
	ExpectedProof   BinaryProofFields `json:"expected_proof"`
}

type ConsistencyVector struct {
	PublicKeyHex     string            `json:"public_key_hex"`
	PartyRandHex     string            `json:"party_randomness_hex"`
	PartyMessage     int               `json:"party_message"`
	PartyCt          [2]string         `json:"party_ciphertext_hex"`
	CandRandomHexes  []string          `json:"cand_randomness_hexes"`
	CandMessages     []int             `json:"cand_messages"`
	CandSumCt        [2]string         `json:"cand_sum_ciphertext_hex"`
	Diff             int               `json:"diff"`
	ExpectedProof    BinaryProofFields `json:"expected_proof"`
}

func hexEncode(b []byte) string {
	return hex.EncodeToString(b)
}

// deterministicScalar creates a scalar from a fixed seed via hash-to-scalar.
// This gives reproducible values for vector generation.
func deterministicScalar(label string) *edwards25519.Scalar {
	return internal.HashToScalar([]byte("otvoren-vot.test-vectors"), []byte(label))
}

func binaryProofFields(p *proof.BinaryProof) BinaryProofFields {
	return BinaryProofFields{
		A0Hex: hexEncode(p.A0.Bytes()),
		B0Hex: hexEncode(p.B0.Bytes()),
		A1Hex: hexEncode(p.A1.Bytes()),
		B1Hex: hexEncode(p.B1.Bytes()),
		E0Hex: hexEncode(p.E0.Bytes()),
		E1Hex: hexEncode(p.E1.Bytes()),
		Z0Hex: hexEncode(p.Z0.Bytes()),
		Z1Hex: hexEncode(p.Z1.Bytes()),
	}
}

// TestGenerateVectors produces deterministic test vectors and writes them to vectors.json.
// Run: go test -run TestGenerateVectors -v ./testdata/
//
// The vectors are generated once in Go and checked into the repo. The TypeScript
// implementation loads them and verifies its own crypto produces identical results
// (for deterministic operations) or successfully verifies (for proofs).
func TestGenerateVectors(t *testing.T) {
	var v Vectors

	// --- Scalar base multiplication vectors ---
	scalarInputs := []struct {
		label string
		value int
	}{
		{"one", 1},
		{"two", 2},
		{"forty-two", 42},
	}
	for _, si := range scalarInputs {
		s := internal.ScalarFromInt(si.value)
		p := new(edwards25519.Point).ScalarBaseMult(s)
		v.ScalarBaseMult = append(v.ScalarBaseMult, ScalarBaseMultVector{
			ScalarHex:        hexEncode(s.Bytes()),
			ExpectedPointHex: hexEncode(p.Bytes()),
		})
	}

	// Also add a hash-derived scalar for non-trivial values.
	bigScalar := deterministicScalar("scalar-base-mult-big")
	bigPoint := new(edwards25519.Point).ScalarBaseMult(bigScalar)
	v.ScalarBaseMult = append(v.ScalarBaseMult, ScalarBaseMultVector{
		ScalarHex:        hexEncode(bigScalar.Bytes()),
		ExpectedPointHex: hexEncode(bigPoint.Bytes()),
	})

	// --- ElGamal encryption vectors ---
	privKey := deterministicScalar("election-private-key")
	pubKey := new(edwards25519.Point).ScalarBaseMult(privKey)

	for _, m := range []int{0, 1} {
		r := deterministicScalar("elgamal-randomness-" + string(rune('0'+m)))
		ct := elgamal.EncryptWithRandomness(pubKey, m, r)
		v.ElGamalEncrypt = append(v.ElGamalEncrypt, ElGamalEncryptVector{
			PublicKeyHex:  hexEncode(pubKey.Bytes()),
			RandomnessHex: hexEncode(r.Bytes()),
			Message:       m,
			ExpectedC1Hex: hexEncode(ct.C1.Bytes()),
			ExpectedC2Hex: hexEncode(ct.C2.Bytes()),
		})
	}

	// --- Fiat-Shamir vectors ---
	fsData1, _ := hex.DecodeString("aabbccdd")
	fsData2, _ := hex.DecodeString("11223344")
	fsResult := internal.FiatShamir("otvoren-vot.test", fsData1)
	v.FiatShamir = append(v.FiatShamir, FiatShamirVector{
		Domain:            "otvoren-vot.test",
		DataHex:           []string{"aabbccdd"},
		ExpectedScalarHex: hexEncode(fsResult.Bytes()),
	})

	fsResult2 := internal.FiatShamir("otvoren-vot.test", fsData1, fsData2)
	v.FiatShamir = append(v.FiatShamir, FiatShamirVector{
		Domain:            "otvoren-vot.test",
		DataHex:           []string{"aabbccdd", "11223344"},
		ExpectedScalarHex: hexEncode(fsResult2.Bytes()),
	})

	// Empty data vector.
	fsResult3 := internal.FiatShamir("otvoren-vot.empty-test")
	v.FiatShamir = append(v.FiatShamir, FiatShamirVector{
		Domain:            "otvoren-vot.empty-test",
		DataHex:           []string{},
		ExpectedScalarHex: hexEncode(fsResult3.Bytes()),
	})

	// --- Binary proof vectors (verify-only) ---
	// Generate a proof with fixed key and randomness. The proof itself uses
	// internal random nonces so it is not deterministic, but the verifier
	// only needs the ciphertext, public key, and proof fields.
	for _, m := range []int{0, 1} {
		r := deterministicScalar("binary-proof-randomness-" + string(rune('0'+m)))
		ct := elgamal.EncryptWithRandomness(pubKey, m, r)
		bp := proof.ProveBinary(pubKey, ct, m, r)

		// Sanity check: proof must verify.
		if !proof.VerifyBinary(pubKey, ct, bp) {
			t.Fatalf("generated binary proof for m=%d does not verify", m)
		}

		v.BinaryProof = append(v.BinaryProof, BinaryProofVector{
			Domain:        "otvoren-vot.ballot-binary-proof",
			PublicKeyHex:  hexEncode(pubKey.Bytes()),
			RandomnessHex: hexEncode(r.Bytes()),
			Message:       m,
			CiphertextC1:  hexEncode(ct.C1.Bytes()),
			CiphertextC2:  hexEncode(ct.C2.Bytes()),
			ExpectedProof: binaryProofFields(bp),
		})
	}

	// --- Candidate sum proof vectors ---
	for _, candSum := range []int{0, 1} {
		numCand := 3
		candRHexes := make([]string, numCand)
		candMsgs := make([]int, numCand)
		candCts := make([]*elgamal.Ciphertext, numCand)
		candRs := make([]*edwards25519.Scalar, numCand)

		for i := range numCand {
			m := 0
			if candSum == 1 && i == 0 {
				m = 1
			}
			candMsgs[i] = m
			r := deterministicScalar("candidate-sum-r-" + string(rune('0'+candSum)) + "-" + string(rune('0'+i)))
			candRs[i] = r
			candRHexes[i] = hexEncode(r.Bytes())
			candCts[i] = elgamal.EncryptWithRandomness(pubKey, m, r)
		}

		aggCt := elgamal.HomomorphicAdd(candCts...)
		rSum := internal.SumScalars(candRs)
		csProof := proof.ProveCandidateSum(pubKey, aggCt, candSum, rSum)

		if !proof.VerifyCandidateSum(pubKey, aggCt, csProof) {
			t.Fatalf("generated candidate sum proof for sum=%d does not verify", candSum)
		}

		v.CandidateSum = append(v.CandidateSum, CandidateSumVector{
			PublicKeyHex:    hexEncode(pubKey.Bytes()),
			CandRandomHexes: candRHexes,
			CandMessages:    candMsgs,
			AggC1Hex:        hexEncode(aggCt.C1.Bytes()),
			AggC2Hex:        hexEncode(aggCt.C2.Bytes()),
			Sum:             candSum,
			ExpectedProof:   binaryProofFields(csProof),
		})
	}

	// --- Consistency proof vectors ---
	type consistencyCase struct {
		partyMsg int
		candSum  int
	}
	cases := []consistencyCase{
		{0, 0}, // diff=0
		{1, 0}, // diff=1
		{1, 1}, // diff=0
	}

	for ci, cc := range cases {
		rParty := deterministicScalar("consistency-party-r-" + string(rune('0'+ci)))
		partyCt := elgamal.EncryptWithRandomness(pubKey, cc.partyMsg, rParty)

		numCand := 2
		candRHexes := make([]string, numCand)
		candMsgs := make([]int, numCand)
		candCts := make([]*elgamal.Ciphertext, numCand)
		candRs := make([]*edwards25519.Scalar, numCand)

		for i := range numCand {
			m := 0
			if cc.candSum == 1 && i == 0 {
				m = 1
			}
			candMsgs[i] = m
			r := deterministicScalar("consistency-cand-r-" + string(rune('0'+ci)) + "-" + string(rune('0'+i)))
			candRs[i] = r
			candRHexes[i] = hexEncode(r.Bytes())
			candCts[i] = elgamal.EncryptWithRandomness(pubKey, m, r)
		}

		candSumCt := elgamal.HomomorphicAdd(candCts...)
		rCandSum := internal.SumScalars(candRs)
		rDiff := new(edwards25519.Scalar).Subtract(rParty, rCandSum)
		diff := cc.partyMsg - cc.candSum

		conProof := proof.ProveConsistency(pubKey, partyCt, candSumCt, diff, rDiff)

		if !proof.VerifyConsistency(pubKey, partyCt, candSumCt, conProof) {
			t.Fatalf("generated consistency proof for case %d does not verify", ci)
		}

		v.Consistency = append(v.Consistency, ConsistencyVector{
			PublicKeyHex:    hexEncode(pubKey.Bytes()),
			PartyRandHex:    hexEncode(rParty.Bytes()),
			PartyMessage:    cc.partyMsg,
			PartyCt:         [2]string{hexEncode(partyCt.C1.Bytes()), hexEncode(partyCt.C2.Bytes())},
			CandRandomHexes: candRHexes,
			CandMessages:    candMsgs,
			CandSumCt:       [2]string{hexEncode(candSumCt.C1.Bytes()), hexEncode(candSumCt.C2.Bytes())},
			Diff:            diff,
			ExpectedProof:   binaryProofFields(conProof),
		})
	}

	// Write vectors to JSON.
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal("failed to marshal vectors:", err)
	}

	outPath := "vectors.json"
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		t.Fatal("failed to write vectors.json:", err)
	}

	t.Logf("wrote %d bytes to %s", len(data), outPath)
}

// TestVerifyVectors loads vectors.json and verifies the deterministic values
// are correct and the proofs verify.
func TestVerifyVectors(t *testing.T) {
	data, err := os.ReadFile("vectors.json")
	if err != nil {
		t.Skip("vectors.json not found; run TestGenerateVectors first")
	}

	var v Vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal("failed to unmarshal vectors.json:", err)
	}

	// Verify scalar base mult vectors.
	for i, sv := range v.ScalarBaseMult {
		sb, _ := hex.DecodeString(sv.ScalarHex)
		s, err := new(edwards25519.Scalar).SetCanonicalBytes(sb)
		if err != nil {
			t.Fatalf("scalar_base_mult[%d]: bad scalar: %v", i, err)
		}
		p := new(edwards25519.Point).ScalarBaseMult(s)
		if hexEncode(p.Bytes()) != sv.ExpectedPointHex {
			t.Fatalf("scalar_base_mult[%d]: point mismatch", i)
		}
	}

	// Verify ElGamal encryption vectors.
	for i, ev := range v.ElGamalEncrypt {
		pkb, _ := hex.DecodeString(ev.PublicKeyHex)
		pk, err := new(edwards25519.Point).SetBytes(pkb)
		if err != nil {
			t.Fatalf("elgamal_encrypt[%d]: bad public key: %v", i, err)
		}
		rb, _ := hex.DecodeString(ev.RandomnessHex)
		r, err := new(edwards25519.Scalar).SetCanonicalBytes(rb)
		if err != nil {
			t.Fatalf("elgamal_encrypt[%d]: bad randomness: %v", i, err)
		}
		ct := elgamal.EncryptWithRandomness(pk, ev.Message, r)
		if hexEncode(ct.C1.Bytes()) != ev.ExpectedC1Hex || hexEncode(ct.C2.Bytes()) != ev.ExpectedC2Hex {
			t.Fatalf("elgamal_encrypt[%d]: ciphertext mismatch", i)
		}
	}

	// Verify Fiat-Shamir vectors.
	for i, fv := range v.FiatShamir {
		dataSlices := make([][]byte, len(fv.DataHex))
		for j, dh := range fv.DataHex {
			dataSlices[j], _ = hex.DecodeString(dh)
		}
		result := internal.FiatShamir(fv.Domain, dataSlices...)
		if hexEncode(result.Bytes()) != fv.ExpectedScalarHex {
			t.Fatalf("fiat_shamir[%d]: scalar mismatch", i)
		}
	}

	// Verify binary proof vectors (verify-only: check that the proof verifies).
	for i, bv := range v.BinaryProof {
		pkb, _ := hex.DecodeString(bv.PublicKeyHex)
		pk, _ := new(edwards25519.Point).SetBytes(pkb)

		c1b, _ := hex.DecodeString(bv.CiphertextC1)
		c1, _ := new(edwards25519.Point).SetBytes(c1b)
		c2b, _ := hex.DecodeString(bv.CiphertextC2)
		c2, _ := new(edwards25519.Point).SetBytes(c2b)
		ct := &elgamal.Ciphertext{C1: c1, C2: c2}

		bp := decodeBinaryProof(t, bv.ExpectedProof)
		if !proof.VerifyBinaryWithDomain(bv.Domain, pk, ct, bp) {
			t.Fatalf("binary_proof[%d]: proof does not verify", i)
		}
	}

	// Verify candidate sum proof vectors.
	for i, csv := range v.CandidateSum {
		pkb, _ := hex.DecodeString(csv.PublicKeyHex)
		pk, _ := new(edwards25519.Point).SetBytes(pkb)

		c1b, _ := hex.DecodeString(csv.AggC1Hex)
		c1, _ := new(edwards25519.Point).SetBytes(c1b)
		c2b, _ := hex.DecodeString(csv.AggC2Hex)
		c2, _ := new(edwards25519.Point).SetBytes(c2b)
		aggCt := &elgamal.Ciphertext{C1: c1, C2: c2}

		csProof := decodeBinaryProof(t, csv.ExpectedProof)
		if !proof.VerifyCandidateSum(pk, aggCt, csProof) {
			t.Fatalf("candidate_sum_proof[%d]: proof does not verify", i)
		}
	}

	// Verify consistency proof vectors.
	for i, cv := range v.Consistency {
		pkb, _ := hex.DecodeString(cv.PublicKeyHex)
		pk, _ := new(edwards25519.Point).SetBytes(pkb)

		pc1b, _ := hex.DecodeString(cv.PartyCt[0])
		pc1, _ := new(edwards25519.Point).SetBytes(pc1b)
		pc2b, _ := hex.DecodeString(cv.PartyCt[1])
		pc2, _ := new(edwards25519.Point).SetBytes(pc2b)
		partyCt := &elgamal.Ciphertext{C1: pc1, C2: pc2}

		cc1b, _ := hex.DecodeString(cv.CandSumCt[0])
		cc1, _ := new(edwards25519.Point).SetBytes(cc1b)
		cc2b, _ := hex.DecodeString(cv.CandSumCt[1])
		cc2, _ := new(edwards25519.Point).SetBytes(cc2b)
		candSumCt := &elgamal.Ciphertext{C1: cc1, C2: cc2}

		conProof := decodeBinaryProof(t, cv.ExpectedProof)
		if !proof.VerifyConsistency(pk, partyCt, candSumCt, conProof) {
			t.Fatalf("consistency_proof[%d]: proof does not verify", i)
		}
	}
}

func decodeBinaryProof(t *testing.T, fields BinaryProofFields) *proof.BinaryProof {
	t.Helper()
	a0b, _ := hex.DecodeString(fields.A0Hex)
	a0, _ := new(edwards25519.Point).SetBytes(a0b)
	b0b, _ := hex.DecodeString(fields.B0Hex)
	b0, _ := new(edwards25519.Point).SetBytes(b0b)
	a1b, _ := hex.DecodeString(fields.A1Hex)
	a1, _ := new(edwards25519.Point).SetBytes(a1b)
	b1b, _ := hex.DecodeString(fields.B1Hex)
	b1, _ := new(edwards25519.Point).SetBytes(b1b)
	e0b, _ := hex.DecodeString(fields.E0Hex)
	e0, _ := new(edwards25519.Scalar).SetCanonicalBytes(e0b)
	e1b, _ := hex.DecodeString(fields.E1Hex)
	e1, _ := new(edwards25519.Scalar).SetCanonicalBytes(e1b)
	z0b, _ := hex.DecodeString(fields.Z0Hex)
	z0, _ := new(edwards25519.Scalar).SetCanonicalBytes(z0b)
	z1b, _ := hex.DecodeString(fields.Z1Hex)
	z1, _ := new(edwards25519.Scalar).SetCanonicalBytes(z1b)
	return &proof.BinaryProof{
		A0: a0, B0: b0, A1: a1, B1: b1,
		E0: e0, E1: e1, Z0: z0, Z1: z1,
	}
}
