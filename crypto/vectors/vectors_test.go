package vectors

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strconv"
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/group"
	"github.com/valy0/otvoren-vot/crypto/internal"
	"github.com/valy0/otvoren-vot/crypto/proof"
)

// Vectors is the top-level test vector structure for cross-language interop.
// Every binary value is lowercase hex. The TypeScript client (PR 2b) consumes
// this exact schema.
type Vectors struct {
	ScalarBaseMult []ScalarBaseMultVector `json:"scalar_base_mult"`
	ElGamalEncrypt []ElGamalEncryptVector `json:"elgamal_encrypt"`
	FiatShamir     []FiatShamirVector     `json:"fiat_shamir"`
	BinaryProof    []BinaryProofVector    `json:"binary_proof"`
	SumOneProof    []SumOneProofVector    `json:"sum_one_proof"`
	CandidateSum   []CandidateSumVector   `json:"candidate_sum_proof"`
	Consistency    []ConsistencyVector    `json:"consistency_proof"`
}

type ScalarBaseMultVector struct {
	ScalarHex        string `json:"scalar_hex"`
	ExpectedPointHex string `json:"expected_point_hex"`
}

type ElGamalEncryptVector struct {
	PublicKeyHex  string `json:"public_key_hex"`
	RandomnessHex string `json:"randomness_hex"`
	Message       int    `json:"message"`
	ExpectedC1Hex string `json:"expected_c1_hex"`
	ExpectedC2Hex string `json:"expected_c2_hex"`
}

type FiatShamirVector struct {
	Domain            string   `json:"domain"`
	DataHex           []string `json:"data_hex"`
	ExpectedScalarHex string   `json:"expected_scalar_hex"`
}

// ContextFields is the ballot-proof context of docs/protocol/fiat-shamir.md.
type ContextFields struct {
	ElectionID string `json:"election_id"`
	BallotID   string `json:"ballot_id"`
	Index      uint32 `json:"index"`
}

type CiphertextFields struct {
	C1Hex string `json:"c1_hex"`
	C2Hex string `json:"c2_hex"`
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

type SumOneProofFields struct {
	AHex string `json:"a_hex"`
	BHex string `json:"b_hex"`
	ZHex string `json:"z_hex"`
}

type BinaryProofVector struct {
	Context      ContextFields     `json:"context"`
	PublicKeyHex string            `json:"public_key_hex"`
	Message      int               `json:"message"`
	CiphertextC1 string            `json:"ciphertext_c1_hex"`
	CiphertextC2 string            `json:"ciphertext_c2_hex"`
	Proof        BinaryProofFields `json:"proof"`
}

type SumOneProofVector struct {
	Context      ContextFields      `json:"context"`
	PublicKeyHex string             `json:"public_key_hex"`
	Ciphertexts  []CiphertextFields `json:"ciphertexts"`
	Proof        SumOneProofFields  `json:"proof"`
}

type CandidateSumVector struct {
	Context      ContextFields     `json:"context"`
	PublicKeyHex string            `json:"public_key_hex"`
	AggC1Hex     string            `json:"agg_c1_hex"`
	AggC2Hex     string            `json:"agg_c2_hex"`
	Sum          int               `json:"sum"`
	Proof        BinaryProofFields `json:"proof"`
}

type ConsistencyVector struct {
	Context           ContextFields     `json:"context"`
	PublicKeyHex      string            `json:"public_key_hex"`
	PartyCiphertext   CiphertextFields  `json:"party_ciphertext"`
	CandSumCiphertext CiphertextFields  `json:"cand_sum_ciphertext"`
	Diff              int               `json:"diff"`
	Proof             BinaryProofFields `json:"proof"`
}

const (
	asciiElection    = "election-2027-national-assembly"
	cyrillicElection = "избори-2027-народно-събрание"
)

func hexEncode(b []byte) string { return hex.EncodeToString(b) }

// deterministicScalar derives a scalar from a label: SHA-512 of the label,
// reduced with SetUniformBytes. Keys and randomness are reproducible; only
// the proof nonces are random.
func deterministicScalar(label string) *ristretto255.Scalar {
	digest := sha512.Sum512([]byte("otvoren-vot.test-vectors." + label))
	s, err := ristretto255.NewScalar().SetUniformBytes(digest[:])
	if err != nil {
		panic(err)
	}
	return s
}

// ballotID is base64url (unpadded) of SHA-256(label): 43 characters.
func ballotID(label string) string {
	sum := sha256.Sum256([]byte(label))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func ctxFields(c proof.Context) ContextFields {
	return ContextFields{ElectionID: c.ElectionID, BallotID: c.BallotID, Index: c.Index}
}

func (c ContextFields) toContext() proof.Context {
	return proof.Context{ElectionID: c.ElectionID, BallotID: c.BallotID, Index: c.Index}
}

func ctFields(ct *elgamal.Ciphertext) CiphertextFields {
	return CiphertextFields{C1Hex: hexEncode(ct.C1.Bytes()), C2Hex: hexEncode(ct.C2.Bytes())}
}

func binaryProofFields(p *proof.BinaryProof) BinaryProofFields {
	return BinaryProofFields{
		A0Hex: hexEncode(p.A0.Bytes()), B0Hex: hexEncode(p.B0.Bytes()),
		A1Hex: hexEncode(p.A1.Bytes()), B1Hex: hexEncode(p.B1.Bytes()),
		E0Hex: hexEncode(p.E0.Bytes()), E1Hex: hexEncode(p.E1.Bytes()),
		Z0Hex: hexEncode(p.Z0.Bytes()), Z1Hex: hexEncode(p.Z1.Bytes()),
	}
}

var update = flag.Bool("update", false, "rewrite testdata/vectors.json from the Go implementation")

// TestGenerateVectors produces test vectors and writes them to testdata/vectors.json.
// Run: go test ./vectors/ -run TestGenerateVectors -update -v
//
// Keys and encryption randomness are deterministic; proof nonces are random,
// so the proof fields differ on every regeneration. The TypeScript
// implementation verifies the proofs and reproduces the deterministic values.
func TestGenerateVectors(t *testing.T) {
	if !*update {
		t.Skip("run with -update to regenerate")
	}
	var v Vectors

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	mustCt := func(pk *ristretto255.Element, m int, r *ristretto255.Scalar) *elgamal.Ciphertext {
		t.Helper()
		ct, err := elgamal.EncryptWithRandomness(pk, m, r)
		must(err)
		return ct
	}

	// --- Scalar base multiplication vectors ---
	var scalars []*ristretto255.Scalar
	for _, n := range []int{1, 2, 42} {
		s, err := internal.ScalarFromInt(n)
		must(err)
		scalars = append(scalars, s)
	}
	scalars = append(scalars, deterministicScalar("scalar-base-mult-big"))
	for _, s := range scalars {
		p := ristretto255.NewIdentityElement().ScalarBaseMult(s)
		v.ScalarBaseMult = append(v.ScalarBaseMult, ScalarBaseMultVector{
			ScalarHex:        hexEncode(s.Bytes()),
			ExpectedPointHex: hexEncode(p.Bytes()),
		})
	}

	// --- ElGamal encryption vectors ---
	privKey := deterministicScalar("election-private-key")
	pubKey := ristretto255.NewIdentityElement().ScalarBaseMult(privKey)
	pkHex := hexEncode(pubKey.Bytes())

	for _, m := range []int{0, 1} {
		r := deterministicScalar("elgamal-randomness-" + itoa(m))
		ct := mustCt(pubKey, m, r)
		v.ElGamalEncrypt = append(v.ElGamalEncrypt, ElGamalEncryptVector{
			PublicKeyHex:  pkHex,
			RandomnessHex: hexEncode(r.Bytes()),
			Message:       m,
			ExpectedC1Hex: hexEncode(ct.C1.Bytes()),
			ExpectedC2Hex: hexEncode(ct.C2.Bytes()),
		})
	}

	// --- Fiat-Shamir vectors ---
	fsData1, _ := hex.DecodeString("aabbccdd")
	fsData2, _ := hex.DecodeString("11223344")
	for _, c := range []struct {
		domain string
		data   [][]byte
		hexes  []string
	}{
		{"otvoren-vot.test", [][]byte{fsData1}, []string{"aabbccdd"}},
		{"otvoren-vot.test", [][]byte{fsData1, fsData2}, []string{"aabbccdd", "11223344"}},
		{"otvoren-vot.empty-test", nil, []string{}},
	} {
		v.FiatShamir = append(v.FiatShamir, FiatShamirVector{
			Domain:            c.domain,
			DataHex:           c.hexes,
			ExpectedScalarHex: hexEncode(internal.FiatShamir(c.domain, c.data...).Bytes()),
		})
	}

	// Contexts: one ASCII and one Cyrillic election per proof kind.
	elections := []string{asciiElection, cyrillicElection}
	newCtx := func(election, kind string, idx uint32) proof.Context {
		return proof.Context{ElectionID: election, BallotID: ballotID(kind + "/" + election), Index: idx}
	}

	// --- Binary proof vectors ---
	for ei, election := range elections {
		for _, m := range []int{0, 1} {
			label := "binary-" + itoa(ei) + "-" + itoa(m)
			r := deterministicScalar(label + "-r")
			ct := mustCt(pubKey, m, r)
			ctx := newCtx(election, label, uint32(ei*2+m))
			bp, err := proof.ProveBinary(ctx, pubKey, ct, m, r)
			must(err)
			must(proof.VerifyBinary(ctx, pubKey, ct, bp))
			v.BinaryProof = append(v.BinaryProof, BinaryProofVector{
				Context:      ctxFields(ctx),
				PublicKeyHex: pkHex,
				Message:      m,
				CiphertextC1: hexEncode(ct.C1.Bytes()),
				CiphertextC2: hexEncode(ct.C2.Bytes()),
				Proof:        binaryProofFields(bp),
			})
		}
	}

	// --- Sum-equals-one proof vectors (3 ciphertexts, the hot one varies) ---
	for ei, election := range elections {
		for hot := 0; hot < 3; hot += 2 {
			label := "sum-one-" + itoa(ei) + "-" + itoa(hot)
			cts := make([]*elgamal.Ciphertext, 3)
			rs := make([]*ristretto255.Scalar, 3)
			for i := range cts {
				m := 0
				if i == hot {
					m = 1
				}
				rs[i] = deterministicScalar(label + "-r-" + itoa(i))
				cts[i] = mustCt(pubKey, m, rs[i])
			}
			ctx := newCtx(election, label, 7)
			sp, err := proof.ProveSumOne(ctx, pubKey, cts, internal.SumScalars(rs))
			must(err)
			must(proof.VerifySumOne(ctx, pubKey, cts, sp))
			sv := SumOneProofVector{
				Context:      ctxFields(ctx),
				PublicKeyHex: pkHex,
				Proof: SumOneProofFields{
					AHex: hexEncode(sp.A.Bytes()),
					BHex: hexEncode(sp.B.Bytes()),
					ZHex: hexEncode(sp.Z.Bytes()),
				},
			}
			for _, ct := range cts {
				sv.Ciphertexts = append(sv.Ciphertexts, ctFields(ct))
			}
			v.SumOneProof = append(v.SumOneProof, sv)
		}
	}

	// candVector encrypts numCand candidate bits with a 1 at position hot
	// (hot < 0: all zero) and returns the aggregate and summed randomness.
	candVector := func(label string, numCand, hot int) (*elgamal.Ciphertext, *ristretto255.Scalar) {
		cts := make([]*elgamal.Ciphertext, numCand)
		rs := make([]*ristretto255.Scalar, numCand)
		for i := range cts {
			m := 0
			if i == hot {
				m = 1
			}
			rs[i] = deterministicScalar(label + "-r-" + itoa(i))
			cts[i] = mustCt(pubKey, m, rs[i])
		}
		return elgamal.HomomorphicAdd(cts...), internal.SumScalars(rs)
	}

	// --- Candidate sum proof vectors ---
	for ei, election := range elections {
		for _, sum := range []int{0, 1} {
			label := "candidate-sum-" + itoa(ei) + "-" + itoa(sum)
			hot := -1
			if sum == 1 {
				hot = 0
			}
			agg, rSum := candVector(label, 3, hot)
			ctx := newCtx(election, label, uint32(ei*2+sum))
			cp, err := proof.ProveCandidateSum(ctx, pubKey, agg, sum, rSum)
			must(err)
			must(proof.VerifyCandidateSum(ctx, pubKey, agg, cp))
			v.CandidateSum = append(v.CandidateSum, CandidateSumVector{
				Context:      ctxFields(ctx),
				PublicKeyHex: pkHex,
				AggC1Hex:     hexEncode(agg.C1.Bytes()),
				AggC2Hex:     hexEncode(agg.C2.Bytes()),
				Sum:          sum,
				Proof:        binaryProofFields(cp),
			})
		}
	}

	// --- Consistency proof vectors (diff = party bit - candidate sum) ---
	for ei, election := range elections {
		for ci, cc := range []struct{ partyMsg, candSum int }{{0, 0}, {1, 0}, {1, 1}} {
			label := "consistency-" + itoa(ei) + "-" + itoa(ci)
			rParty := deterministicScalar(label + "-party-r")
			partyCt := mustCt(pubKey, cc.partyMsg, rParty)
			hot := -1
			if cc.candSum == 1 {
				hot = 0
			}
			candSumCt, rCand := candVector(label, 2, hot)
			rDiff := ristretto255.NewScalar().Subtract(rParty, rCand)
			diff := cc.partyMsg - cc.candSum
			ctx := newCtx(election, label, uint32(ci))
			cp, err := proof.ProveConsistency(ctx, pubKey, partyCt, candSumCt, diff, rDiff)
			must(err)
			must(proof.VerifyConsistency(ctx, pubKey, partyCt, candSumCt, cp))
			v.Consistency = append(v.Consistency, ConsistencyVector{
				Context:           ctxFields(ctx),
				PublicKeyHex:      pkHex,
				PartyCiphertext:   ctFields(partyCt),
				CandSumCiphertext: ctFields(candSumCt),
				Diff:              diff,
				Proof:             binaryProofFields(cp),
			})
		}
	}

	data, err := json.MarshalIndent(v, "", "  ")
	must(err)
	data = append(data, '\n')
	must(os.WriteFile("testdata/vectors.json", data, 0o644))
	t.Logf("wrote %d bytes to testdata/vectors.json", len(data))
}

func loadVectors(t *testing.T) Vectors {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal("testdata/vectors.json not found; run: go test ./vectors/ -run TestGenerateVectors -update")
	}
	var v Vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal("failed to unmarshal vectors.json:", err)
	}
	return v
}

func hasNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
}

// TestVectorsIncludeNonASCIIContext requires, per proof kind, one vector with a
// non-ASCII election_id and one with an ASCII one, and well-formed ballot ids.
func TestVectorsIncludeNonASCIIContext(t *testing.T) {
	v := loadVectors(t)
	kinds := map[string][]ContextFields{}
	for _, x := range v.BinaryProof {
		kinds["binary_proof"] = append(kinds["binary_proof"], x.Context)
	}
	for _, x := range v.SumOneProof {
		kinds["sum_one_proof"] = append(kinds["sum_one_proof"], x.Context)
	}
	for _, x := range v.CandidateSum {
		kinds["candidate_sum_proof"] = append(kinds["candidate_sum_proof"], x.Context)
	}
	for _, x := range v.Consistency {
		kinds["consistency_proof"] = append(kinds["consistency_proof"], x.Context)
	}
	for _, kind := range []string{"binary_proof", "sum_one_proof", "candidate_sum_proof", "consistency_proof"} {
		var nonASCII, ascii bool
		for _, c := range kinds[kind] {
			if hasNonASCII(c.ElectionID) {
				nonASCII = true
			} else {
				ascii = true
			}
			raw, err := base64.RawURLEncoding.DecodeString(c.BallotID)
			if err != nil || len(c.BallotID) != 43 || len(raw) != 32 {
				t.Fatalf("%s: ballot_id %q is not 43-char unpadded base64url of 32 bytes", kind, c.BallotID)
			}
		}
		if !nonASCII {
			t.Errorf("%s: no vector with a non-ASCII election_id", kind)
		}
		if !ascii {
			t.Errorf("%s: no vector with an ASCII election_id", kind)
		}
	}
}

func dElement(t *testing.T, where, h string) *ristretto255.Element {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("%s: bad hex: %v", where, err)
	}
	e, err := group.DecodeElement(b)
	if err != nil {
		t.Fatalf("%s: bad element: %v", where, err)
	}
	return e
}

func dScalar(t *testing.T, where, h string) *ristretto255.Scalar {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("%s: bad hex: %v", where, err)
	}
	s, err := group.DecodeScalar(b)
	if err != nil {
		t.Fatalf("%s: bad scalar: %v", where, err)
	}
	return s
}

func dCiphertext(t *testing.T, where string, c CiphertextFields) *elgamal.Ciphertext {
	t.Helper()
	b, err := hex.DecodeString(c.C1Hex + c.C2Hex)
	if err != nil {
		t.Fatalf("%s: bad hex: %v", where, err)
	}
	ct, err := elgamal.CiphertextFromBytes(b)
	if err != nil {
		t.Fatalf("%s: bad ciphertext: %v", where, err)
	}
	return ct
}

func decodeBinaryProof(t *testing.T, where string, f BinaryProofFields) *proof.BinaryProof {
	t.Helper()
	return &proof.BinaryProof{
		A0: dElement(t, where+".a0", f.A0Hex), B0: dElement(t, where+".b0", f.B0Hex),
		A1: dElement(t, where+".a1", f.A1Hex), B1: dElement(t, where+".b1", f.B1Hex),
		E0: dScalar(t, where+".e0", f.E0Hex), E1: dScalar(t, where+".e1", f.E1Hex),
		Z0: dScalar(t, where+".z0", f.Z0Hex), Z1: dScalar(t, where+".z1", f.Z1Hex),
	}
}

// requireInvalid asserts err is a failed verification, not malformed input.
func requireInvalid(t *testing.T, where string, err error) {
	t.Helper()
	if !errors.Is(err, proof.ErrInvalidProof) {
		t.Fatalf("%s: wrong context should give ErrInvalidProof, got %v", where, err)
	}
}

// TestVerifyVectors loads vectors.json, checks the deterministic values and
// verifies every proof, and that each proof fails under Index+1.
func TestVerifyVectors(t *testing.T) {
	v := loadVectors(t)

	for name, n := range map[string]int{
		"scalar_base_mult": len(v.ScalarBaseMult), "elgamal_encrypt": len(v.ElGamalEncrypt),
		"fiat_shamir": len(v.FiatShamir), "binary_proof": len(v.BinaryProof),
		"sum_one_proof": len(v.SumOneProof), "candidate_sum_proof": len(v.CandidateSum),
		"consistency_proof": len(v.Consistency),
	} {
		if n == 0 {
			t.Fatalf("category %s is empty", name)
		}
	}

	for i, sv := range v.ScalarBaseMult {
		w := "scalar_base_mult[" + itoa(i) + "]"
		s := dScalar(t, w, sv.ScalarHex)
		p := ristretto255.NewIdentityElement().ScalarBaseMult(s)
		if hexEncode(p.Bytes()) != sv.ExpectedPointHex {
			t.Fatalf("%s: point mismatch", w)
		}
	}

	for i, ev := range v.ElGamalEncrypt {
		w := "elgamal_encrypt[" + itoa(i) + "]"
		pk := dElement(t, w+".pk", ev.PublicKeyHex)
		r := dScalar(t, w+".r", ev.RandomnessHex)
		ct, err := elgamal.EncryptWithRandomness(pk, ev.Message, r)
		if err != nil {
			t.Fatalf("%s: %v", w, err)
		}
		if hexEncode(ct.C1.Bytes()) != ev.ExpectedC1Hex || hexEncode(ct.C2.Bytes()) != ev.ExpectedC2Hex {
			t.Fatalf("%s: ciphertext mismatch", w)
		}
	}

	for i, fv := range v.FiatShamir {
		w := "fiat_shamir[" + itoa(i) + "]"
		dataSlices := make([][]byte, len(fv.DataHex))
		for j, dh := range fv.DataHex {
			b, err := hex.DecodeString(dh)
			if err != nil {
				t.Fatalf("%s: bad hex: %v", w, err)
			}
			dataSlices[j] = b
		}
		result := internal.FiatShamir(fv.Domain, dataSlices...)
		if hexEncode(result.Bytes()) != fv.ExpectedScalarHex {
			t.Fatalf("%s: scalar mismatch", w)
		}
	}

	for i, bv := range v.BinaryProof {
		w := "binary_proof[" + itoa(i) + "]"
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
		pk := dElement(t, w+".pk", sv.PublicKeyHex)
		if len(sv.Ciphertexts) < 3 {
			t.Fatalf("%s: want at least 3 ciphertexts, got %d", w, len(sv.Ciphertexts))
		}
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
		ctx.Index++
		requireInvalid(t, w, proof.VerifySumOne(ctx, pk, cts, sp))
	}

	for i, cv := range v.CandidateSum {
		w := "candidate_sum_proof[" + itoa(i) + "]"
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
}

func itoa(i int) string { return strconv.Itoa(i) }
