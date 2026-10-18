package threshold

import (
	"crypto/sha256"
	"errors"
	"math"
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
	"github.com/valy0/otvoren-vot/crypto/proof"
)

// The example election identifier of docs/protocol/fiat-shamir.md.
const testElectionID = "избори-2027-народно-събрание"

// mustEncrypt encrypts m under pk.
func mustEncrypt(t *testing.T, pk *ristretto255.Element, m int) *elgamal.Ciphertext {
	t.Helper()
	ct, _, err := elgamal.Encrypt(pk, m)
	if err != nil {
		t.Fatalf("Encrypt(%d): %v", m, err)
	}
	return ct
}

// testSlotContext is the context of slot 0 of a one-slot tally holding ct.
func testSlotContext(ct *elgamal.Ciphertext) SlotContext {
	return SlotContext{
		ElectionID:    testElectionID,
		SlotIndex:     0,
		TallyDigest:   TallyDigest([]*elgamal.Ciphertext{ct}),
		SetCommitment: sha256.Sum256([]byte("set commitment")),
		SealedHead:    sha256.Sum256([]byte("sealed head")),
	}
}

// fixture is a single-dealer 5-of-9 sharing and one ciphertext under its key.
type fixture struct {
	dealer *Dealer
	ct     *elgamal.Ciphertext
	sc     SlotContext
	keys   map[int]*ristretto255.Element
}

func newFixture(t *testing.T, m int) *fixture {
	t.Helper()
	dealer := mustDealer(t, 5, 9)
	ct := mustEncrypt(t, dealer.PublicKey(), m)
	keys := make(map[int]*ristretto255.Element, len(dealer.Shares))
	for i, s := range dealer.Shares {
		keys[i+1] = ristretto255.NewIdentityElement().ScalarBaseMult(s)
	}
	return &fixture{dealer: dealer, ct: ct, sc: testSlotContext(ct), keys: keys}
}

// partial is trustee idx's partial decryption of the fixture's ciphertext.
func (f *fixture) partial(t *testing.T, idx int) *Partial {
	t.Helper()
	p, err := PartialDecrypt(f.sc, idx, f.dealer.Shares[idx-1], f.ct)
	if err != nil {
		t.Fatalf("trustee %d: PartialDecrypt: %v", idx, err)
	}
	return p
}

func (f *fixture) partials(t *testing.T, indices ...int) []*Partial {
	t.Helper()
	out := make([]*Partial, len(indices))
	for i, idx := range indices {
		out[i] = f.partial(t, idx)
	}
	return out
}

// requireInvalidProof fails unless err wraps proof.ErrInvalidProof.
func requireInvalidProof(t *testing.T, err error, what string) {
	t.Helper()
	if !errors.Is(err, proof.ErrInvalidProof) {
		t.Fatalf("%s: got %v, want proof.ErrInvalidProof", what, err)
	}
}

func TestPartialDecryptAndCombine(t *testing.T) {
	f := newFixture(t, 42)
	partials := f.partials(t, 1, 3, 5, 7, 9)

	m, err := Combine(f.sc, f.ct, partials, f.keys, 5, 100)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if m != 42 {
		t.Fatalf("expected 42, got %d", m)
	}
}

func TestPartialDecryptionProof(t *testing.T) {
	f := newFixture(t, 1)
	pd := f.partial(t, 1)
	if pd.TrusteeIndex != 1 {
		t.Fatalf("TrusteeIndex = %d, want 1", pd.TrusteeIndex)
	}
	if err := VerifyPartial(f.sc, f.ct, pd, f.keys[1]); err != nil {
		t.Fatalf("valid partial decryption proof should verify: %v", err)
	}
}

func TestPartialDecryptionProofInvalid(t *testing.T) {
	f := newFixture(t, 1)
	pd := f.partial(t, 1)
	wrongVK := f.keys[2] // another trustee's key
	requireInvalidProof(t, VerifyPartial(f.sc, f.ct, pd, wrongVK), "proof checked against the wrong verification key")
}

// TestPartialBindsWholeCiphertext: a partial checked by the trustees must not
// verify once c2 is swapped for c2+G, which would add one vote to the slot.
func TestPartialBindsWholeCiphertext(t *testing.T) {
	f := newFixture(t, 5)
	pd := f.partial(t, 1)
	if err := VerifyPartial(f.sc, f.ct, pd, f.keys[1]); err != nil {
		t.Fatalf("valid partial should verify: %v", err)
	}

	bumped := &elgamal.Ciphertext{
		C1: f.ct.C1,
		C2: ristretto255.NewIdentityElement().Add(f.ct.C2, ristretto255.NewGeneratorElement()),
	}
	requireInvalidProof(t, VerifyPartial(f.sc, bumped, pd, f.keys[1]), "partial against (c1, c2+G)")

	partials := f.partials(t, 1, 2, 3, 4, 5)
	m, err := Combine(f.sc, bumped, partials, f.keys, 5, 100)
	if !errors.Is(err, proof.ErrInvalidProof) {
		t.Fatalf("Combine against (c1, c2+G) = (%d, %v), want proof.ErrInvalidProof", m, err)
	}
}

func TestPartialBindsContextFields(t *testing.T) {
	f := newFixture(t, 5)
	pd := f.partial(t, 3)
	vk := f.keys[3]
	if err := VerifyPartial(f.sc, f.ct, pd, vk); err != nil {
		t.Fatalf("valid partial should verify: %v", err)
	}

	flip := func(d [32]byte) [32]byte { d[0] ^= 1; return d }
	for _, tc := range []struct {
		name   string
		mutate func(*SlotContext)
	}{
		{"ElectionID", func(sc *SlotContext) { sc.ElectionID = "избори-2027-президент" }},
		{"SlotIndex", func(sc *SlotContext) { sc.SlotIndex++ }},
		{"TallyDigest", func(sc *SlotContext) { sc.TallyDigest = flip(sc.TallyDigest) }},
		{"SetCommitment", func(sc *SlotContext) { sc.SetCommitment = flip(sc.SetCommitment) }},
		{"SealedHead", func(sc *SlotContext) { sc.SealedHead = flip(sc.SealedHead) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := f.sc
			tc.mutate(&sc)
			requireInvalidProof(t, VerifyPartial(sc, f.ct, pd, vk), "changed "+tc.name)
		})
	}

	t.Run("TrusteeIndex", func(t *testing.T) {
		// Same D and proof, same key, relabelled to another trustee.
		relabelled := &Partial{TrusteeIndex: 4, D: pd.D, Proof: pd.Proof}
		requireInvalidProof(t, VerifyPartial(f.sc, f.ct, relabelled, vk), "changed TrusteeIndex")
	})
}

func TestPartialRejectsMalformed(t *testing.T) {
	f := newFixture(t, 1)
	share := f.dealer.Shares[0]
	empty := f.sc
	empty.ElectionID = ""
	// 2^32 where int is 64 bits (it wraps to 0 elsewhere, still a bad
	// index). u32be(2^32 + 1) would alias trustee 1 in the transcript.
	var maxU32 uint64 = math.MaxUint32
	pastU32 := int(maxU32 + 1)

	for _, tc := range []struct {
		name  string
		sc    SlotContext
		idx   int
		share *ristretto255.Scalar
		ct    *elgamal.Ciphertext
		want  error
	}{
		{"empty election id", empty, 1, share, f.ct, proof.ErrMalformed},
		{"nil share", f.sc, 1, nil, f.ct, proof.ErrMalformed},
		{"nil ciphertext", f.sc, 1, share, nil, proof.ErrMalformed},
		{"nil c1", f.sc, 1, share, &elgamal.Ciphertext{C2: f.ct.C2}, proof.ErrMalformed},
		{"nil c2", f.sc, 1, share, &elgamal.Ciphertext{C1: f.ct.C1}, proof.ErrMalformed},
		{"index 0", f.sc, 0, share, f.ct, ErrBadIndex},
		{"negative index", f.sc, -1, share, f.ct, ErrBadIndex},
		{"index past u32", f.sc, pastU32, share, f.ct, ErrBadIndex},
	} {
		t.Run("PartialDecrypt/"+tc.name, func(t *testing.T) {
			defer noPanic(t)
			if _, err := PartialDecrypt(tc.sc, tc.idx, tc.share, tc.ct); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	pd := f.partial(t, 1)
	vk := f.keys[1]
	for _, tc := range []struct {
		name string
		sc   SlotContext
		ct   *elgamal.Ciphertext
		p    *Partial
		vk   *ristretto255.Element
		want error
	}{
		{"empty election id", empty, f.ct, pd, vk, proof.ErrMalformed},
		{"nil ciphertext", f.sc, nil, pd, vk, proof.ErrMalformed},
		{"nil c1", f.sc, &elgamal.Ciphertext{C2: f.ct.C2}, pd, vk, proof.ErrMalformed},
		{"nil c2", f.sc, &elgamal.Ciphertext{C1: f.ct.C1}, pd, vk, proof.ErrMalformed},
		{"nil partial", f.sc, f.ct, nil, vk, proof.ErrMalformed},
		{"nil D", f.sc, f.ct, &Partial{TrusteeIndex: 1, Proof: pd.Proof}, vk, proof.ErrMalformed},
		{"nil proof", f.sc, f.ct, &Partial{TrusteeIndex: 1, D: pd.D}, vk, proof.ErrMalformed},
		{"nil proof field", f.sc, f.ct, &Partial{TrusteeIndex: 1, D: pd.D, Proof: &proof.ChaumPedersenProof{U: pd.Proof.U, V: pd.Proof.V}}, vk, proof.ErrMalformed},
		{"nil key", f.sc, f.ct, pd, nil, proof.ErrMalformed},
		{"index 0", f.sc, f.ct, &Partial{TrusteeIndex: 0, D: pd.D, Proof: pd.Proof}, vk, ErrBadIndex},
		{"index past u32", f.sc, f.ct, &Partial{TrusteeIndex: pastU32 + 1, D: pd.D, Proof: pd.Proof}, vk, ErrBadIndex},
	} {
		t.Run("VerifyPartial/"+tc.name, func(t *testing.T) {
			defer noPanic(t)
			if err := VerifyPartial(tc.sc, tc.ct, tc.p, tc.vk); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// noPanic turns a panic in the calling test into a test failure.
func noPanic(t *testing.T) {
	t.Helper()
	if r := recover(); r != nil {
		t.Fatalf("panicked: %v", r)
	}
}

// TestCombineRejects is M22: no combination without exactly threshold
// distinct, known and verified partials.
func TestCombineRejects(t *testing.T) {
	f := newFixture(t, 9)

	// valid returns fresh copies of five valid partials, so cases can edit them.
	valid := func() []*Partial {
		ps := f.partials(t, 1, 2, 3, 4, 5)
		for i, p := range ps {
			c := *p
			ps[i] = &c
		}
		return ps
	}
	// Sanity: the unedited set combines.
	if m, err := Combine(f.sc, f.ct, valid(), f.keys, 5, 100); err != nil || m != 9 {
		t.Fatalf("valid set: Combine = (%d, %v), want (9, nil)", m, err)
	}

	missing4 := make(map[int]*ristretto255.Element)
	for k, v := range f.keys {
		if k != 4 {
			missing4[k] = v
		}
	}
	nilKey4 := make(map[int]*ristretto255.Element)
	for k, v := range f.keys {
		nilKey4[k] = v
	}
	nilKey4[4] = nil

	for _, tc := range []struct {
		name         string
		partials     func() []*Partial
		keys         map[int]*ristretto255.Element
		threshold    int
		maxPlaintext int
		want         error // nil: any error will do
	}{
		{"duplicate index", func() []*Partial {
			ps := valid()
			ps[4] = f.partial(t, 1)
			return ps
		}, f.keys, 5, 100, ErrDuplicateIndex},
		{"index 0", func() []*Partial {
			ps := valid()
			ps[0].TrusteeIndex = 0
			return ps
		}, f.keys, 5, 100, ErrBadIndex},
		{"negative index", func() []*Partial {
			ps := valid()
			ps[2].TrusteeIndex = -3
			return ps
		}, f.keys, 5, 100, ErrBadIndex},
		{"4 partials", func() []*Partial { return valid()[:4] }, f.keys, 5, 100, ErrPartialCount},
		{"6 partials", func() []*Partial { return append(valid(), f.partial(t, 6)) }, f.keys, 5, 100, ErrPartialCount},
		{"no partials", func() []*Partial { return nil }, f.keys, 5, 100, ErrPartialCount},
		{"nil partial", func() []*Partial {
			ps := valid()
			ps[1] = nil
			return ps
		}, f.keys, 5, 100, proof.ErrMalformed},
		{"nil proof", func() []*Partial {
			ps := valid()
			ps[3].Proof = nil
			return ps
		}, f.keys, 5, 100, proof.ErrMalformed},
		{"nil D", func() []*Partial {
			ps := valid()
			ps[3].D = nil
			return ps
		}, f.keys, 5, 100, proof.ErrMalformed},
		{"bad proof (tampered D)", func() []*Partial {
			ps := valid()
			ps[2].D = ristretto255.NewIdentityElement().Add(ps[2].D, ristretto255.NewGeneratorElement())
			return ps
		}, f.keys, 5, 100, proof.ErrInvalidProof},
		{"relabelled partial", func() []*Partial {
			ps := valid()
			ps[4].TrusteeIndex = 6 // trustee 5's D and proof under trustee 6's key
			return ps
		}, f.keys, 5, 100, proof.ErrInvalidProof},
		{"trustee not in keys", valid, missing4, 5, 100, ErrUnknownTrustee},
		{"nil keys", valid, nil, 5, 100, ErrUnknownTrustee},
		{"nil key", valid, nilKey4, 5, 100, proof.ErrMalformed},
		{"threshold 0", func() []*Partial { return nil }, f.keys, 0, 100, nil},
		{"negative maxPlaintext", valid, f.keys, 5, -1, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer noPanic(t)
			m, err := Combine(f.sc, f.ct, tc.partials(), tc.keys, tc.threshold, tc.maxPlaintext)
			if err == nil {
				t.Fatalf("Combine = %d, want an error", m)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("malformed context", func(t *testing.T) {
		defer noPanic(t)
		sc := f.sc
		sc.ElectionID = ""
		if _, err := Combine(sc, f.ct, valid(), f.keys, 5, 100); !errors.Is(err, proof.ErrMalformed) {
			t.Fatalf("empty election id: got %v, want proof.ErrMalformed", err)
		}
		if _, err := Combine(f.sc, nil, valid(), f.keys, 5, 100); !errors.Is(err, proof.ErrMalformed) {
			t.Fatalf("nil ciphertext: got %v, want proof.ErrMalformed", err)
		}
	})
}

func TestCombineOutOfRange(t *testing.T) {
	f := newFixture(t, 101)
	partials := f.partials(t, 2, 4, 6, 8, 9)

	m, err := Combine(f.sc, f.ct, partials, f.keys, 5, 100)
	if !errors.Is(err, ErrPlaintextOutOfRange) {
		t.Fatalf("plaintext 101 with max 100: got (%d, %v), want ErrPlaintextOutOfRange", m, err)
	}

	m, err = Combine(f.sc, f.ct, partials, f.keys, 5, 101)
	if err != nil || m != 101 {
		t.Fatalf("plaintext 101 with max 101: got (%d, %v), want (101, nil)", m, err)
	}
}

func TestTallyDigest(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	a := mustEncrypt(t, kp.PublicKey, 1)
	b := mustEncrypt(t, kp.PublicKey, 2)

	ab := TallyDigest([]*elgamal.Ciphertext{a, b})
	if ab != TallyDigest([]*elgamal.Ciphertext{a, b}) {
		t.Fatal("TallyDigest should be deterministic")
	}
	if ab == TallyDigest([]*elgamal.Ciphertext{b, a}) {
		t.Fatal("TallyDigest should depend on slot order")
	}
	if ab == TallyDigest([]*elgamal.Ciphertext{a}) {
		t.Fatal("TallyDigest should depend on every slot")
	}
	swappedC2 := &elgamal.Ciphertext{C1: b.C1, C2: ristretto255.NewIdentityElement().Add(b.C2, ristretto255.NewGeneratorElement())}
	if ab == TallyDigest([]*elgamal.Ciphertext{a, swappedC2}) {
		t.Fatal("TallyDigest should depend on c2")
	}
	swappedC1 := &elgamal.Ciphertext{C1: ristretto255.NewIdentityElement().Add(b.C1, ristretto255.NewGeneratorElement()), C2: b.C2}
	if ab == TallyDigest([]*elgamal.Ciphertext{a, swappedC1}) {
		t.Fatal("TallyDigest should depend on c1")
	}
}

// TestPartialTranscriptFollowsSpec rebuilds the partial-decryption challenge
// field by field from docs/protocol/fiat-shamir.md ("Partial-Decryption Proof
// (Chaum-Pedersen)"), with hand-built byte slices and a tally digest computed
// directly with crypto/sha256, so a reordered or dropped field fails here even
// though prover and verifier would still agree with each other.
func TestPartialTranscriptFollowsSpec(t *testing.T) {
	dealer := mustDealer(t, 5, 9)
	pk := dealer.PublicKey()
	cts := []*elgamal.Ciphertext{mustEncrypt(t, pk, 4), mustEncrypt(t, pk, 7), mustEncrypt(t, pk, 0)}

	// tally_digest = SHA-256(lp("otvoren-vot.tally-vector") || lp(c1_0 || c2_0) || ...)
	tallyDomain := []byte("otvoren-vot.tally-vector")
	if len(tallyDomain) != 24 {
		t.Fatalf("tally-vector domain is %d bytes, fiat-shamir.md says 24", len(tallyDomain))
	}
	digestInput := append([]byte{0x00, 0x00, 0x00, 0x18}, tallyDomain...)
	for _, ct := range cts {
		digestInput = append(digestInput, 0x00, 0x00, 0x00, 0x40)
		digestInput = append(digestInput, ct.C1.Bytes()...)
		digestInput = append(digestInput, ct.C2.Bytes()...)
	}
	wantDigest := sha256.Sum256(digestInput)
	if got := TallyDigest(cts); got != wantDigest {
		t.Fatalf("TallyDigest = %x, want %x", got, wantDigest)
	}

	const trustee = 3 // Shamir index i
	const slot = 1    // 0-based canonical slot position
	ct := cts[slot]
	setCommitment := sha256.Sum256([]byte("set commitment"))
	sealedHead := sha256.Sum256([]byte("sealed head"))
	sc := SlotContext{
		ElectionID:    testElectionID,
		SlotIndex:     slot,
		TallyDigest:   wantDigest,
		SetCommitment: setCommitment,
		SealedHead:    sealedHead,
	}

	share := dealer.Shares[trustee-1]
	p, err := PartialDecrypt(sc, trustee, share, ct)
	if err != nil {
		t.Fatalf("PartialDecrypt: %v", err)
	}
	if p.TrusteeIndex != trustee {
		t.Fatalf("TrusteeIndex = %d, want %d", p.TrusteeIndex, trustee)
	}
	if p.D.Equal(ristretto255.NewIdentityElement().ScalarMult(share, ct.C1)) != 1 {
		t.Fatal("D should be x_i * c1")
	}

	G := ristretto255.NewGeneratorElement()
	hi := ristretto255.NewIdentityElement().ScalarBaseMult(share)

	// The domain, then fields 2-8 (the seven context fields), then field 9
	// (G, c1, h_i, d_i, u, v), each length-prefixed by FiatShamir.
	fields := [][]byte{
		[]byte(testElectionID),   // 2. utf8(election_id)
		{0x00, 0x00, 0x00, 0x03}, // 3. u32be(trustee_index)
		{0x00, 0x00, 0x00, 0x01}, // 4. u32be(slot_index)
		ct.C2.Bytes(),            // 5. c2 of the slot's ciphertext
		wantDigest[:],            // 6. tally_digest
		setCommitment[:],         // 7. set_commitment
		sealedHead[:],            // 8. sealed_head
		G.Bytes(),                // 9. G
		ct.C1.Bytes(),            //    c1
		hi.Bytes(),               //    h_i
		p.D.Bytes(),              //    d_i
		p.Proof.U.Bytes(),        //    u
		p.Proof.V.Bytes(),        //    v
	}
	e := internal.FiatShamir("otvoren-vot.chaum-pedersen", fields...)

	// z*G == u + e*h_i and z*c1 == v + e*d_i hold only for the challenge the
	// prover used.
	lhs := ristretto255.NewIdentityElement().ScalarBaseMult(p.Proof.Z)
	rhs := ristretto255.NewIdentityElement().ScalarMult(e, hi)
	rhs.Add(p.Proof.U, rhs)
	if lhs.Equal(rhs) != 1 {
		t.Fatal("challenge does not match the fiat-shamir.md transcript (G equation)")
	}
	lhs = ristretto255.NewIdentityElement().ScalarMult(p.Proof.Z, ct.C1)
	rhs = ristretto255.NewIdentityElement().ScalarMult(e, p.D)
	rhs.Add(p.Proof.V, rhs)
	if lhs.Equal(rhs) != 1 {
		t.Fatal("challenge does not match the fiat-shamir.md transcript (c1 equation)")
	}

	if err := VerifyPartial(sc, ct, p, hi); err != nil {
		t.Fatalf("VerifyPartial: %v", err)
	}
}
