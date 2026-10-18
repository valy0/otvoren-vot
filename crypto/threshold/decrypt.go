package threshold

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
	"github.com/valy0/otvoren-vot/crypto/proof"
)

var (
	// ErrPartialCount is returned when Combine is not given exactly
	// threshold partial decryptions.
	ErrPartialCount = errors.New("threshold: wrong number of partial decryptions")
	// ErrUnknownTrustee is returned for a partial decryption whose trustee
	// index has no verification key.
	ErrUnknownTrustee = errors.New("threshold: no verification key for trustee")
	// ErrPlaintextOutOfRange is returned when the combined plaintext is not
	// in [0, maxPlaintext].
	ErrPlaintextOutOfRange = errors.New("threshold: plaintext out of range")
)

// tallyVectorDomain separates the tally digest (docs/protocol/fiat-shamir.md,
// "Partial-Decryption Proof (Chaum-Pedersen)").
const tallyVectorDomain = "otvoren-vot.tally-vector"

// SlotContext is the transcript context of a partial decryption of one tally
// slot (docs/protocol/fiat-shamir.md, "Partial-Decryption Proof
// (Chaum-Pedersen)"). It binds the partial to one election, one slot, one
// exact tally vector, one ballot set and one board state; the trustee index
// and the slot's c2 complete the context.
type SlotContext struct {
	ElectionID    string
	SlotIndex     uint32   // 0-based position in the canonical slot order
	TallyDigest   [32]byte // TallyDigest of the published tally vector
	SetCommitment [32]byte // Collection's SHA-256 commitment to the active ballot set
	SealedHead    [32]byte // SHA-256 of the board's sealed signed head
}

// Partial is one trustee's partial decryption D = x_i * c1 of a tally slot,
// with a Chaum-Pedersen proof that log_G(h_i) = log_c1(D).
type Partial struct {
	TrusteeIndex int // Shamir index i, 1-based
	D            *ristretto255.Element
	Proof        *proof.ChaumPedersenProof
}

// TallyDigest computes
//
//	SHA-256(lp("otvoren-vot.tally-vector") || lp(c1_0 || c2_0) || ... || lp(c1_{n-1} || c2_{n-1}))
//
// over the published tally vector in canonical slot order, where lp(x) is
// u32be(len(x)) || x.
//
// cts must be decoded ciphertexts: every entry non-nil with non-nil C1 and
// C2, as elgamal.CiphertextFromBytes returns them. Callers decode the
// published vector before digesting it; Combine and VerifyPartial take the
// digest from SlotContext and never call TallyDigest.
func TallyDigest(cts []*elgamal.Ciphertext) [32]byte {
	h := sha256.New()
	writeLP := func(b []byte) {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(b))))
		h.Write(b)
	}
	writeLP([]byte(tallyVectorDomain))
	for _, ct := range cts {
		writeLP(ct.Bytes())
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// PartialDecrypt computes trustee trusteeIndex's partial decryption
// D = share * c1 of ct, with a Chaum-Pedersen proof bound to sc, the trustee
// index and ct's c2. The proof statement is (G, c1, h_i, D) with
// h_i = share * G.
func PartialDecrypt(sc SlotContext, trusteeIndex int, share *ristretto255.Scalar, ct *elgamal.Ciphertext) (*Partial, error) {
	if err := checkSlot(sc, ct); err != nil {
		return nil, err
	}
	if err := checkIndex(trusteeIndex); err != nil {
		return nil, fmt.Errorf("threshold: partial decrypt: %w", err)
	}
	if share == nil {
		return nil, fmt.Errorf("threshold: partial decrypt: nil share: %w", proof.ErrMalformed)
	}

	G := ristretto255.NewGeneratorElement()
	d := ristretto255.NewIdentityElement().ScalarMult(share, ct.C1)
	hi := ristretto255.NewIdentityElement().ScalarBaseMult(share)
	p, err := proof.ProveChaumPedersen(partialContext(sc, trusteeIndex, ct.C2), G, ct.C1, hi, d, share)
	if err != nil {
		return nil, fmt.Errorf("threshold: partial decrypt: %w", err)
	}
	return &Partial{TrusteeIndex: trusteeIndex, D: d, Proof: p}, nil
}

// VerifyPartial checks p's proof against the trustee's verification key h_i,
// under sc, p.TrusteeIndex and ct's c2. It returns nil for a valid partial,
// an error wrapping proof.ErrInvalidProof when the proof fails, one wrapping
// proof.ErrMalformed for an empty ElectionID or a nil input, and one
// wrapping ErrBadIndex for a trustee index outside 1..2^32-1.
func VerifyPartial(sc SlotContext, ct *elgamal.Ciphertext, p *Partial, verificationKey *ristretto255.Element) error {
	if err := checkSlot(sc, ct); err != nil {
		return err
	}
	if p == nil || p.D == nil || p.Proof == nil {
		return fmt.Errorf("threshold: verify partial: nil partial, D or proof: %w", proof.ErrMalformed)
	}
	if verificationKey == nil {
		return fmt.Errorf("threshold: verify partial: nil verification key: %w", proof.ErrMalformed)
	}
	if err := checkIndex(p.TrusteeIndex); err != nil {
		return fmt.Errorf("threshold: verify partial: %w", err)
	}

	G := ristretto255.NewGeneratorElement()
	if err := proof.VerifyChaumPedersen(partialContext(sc, p.TrusteeIndex, ct.C2), G, ct.C1, verificationKey, p.D, p.Proof); err != nil {
		return fmt.Errorf("threshold: verify partial: %w", err)
	}
	return nil
}

// Combine recovers the plaintext of ct from exactly threshold partial
// decryptions. It rejects, in order: a partial count other than threshold
// (ErrPartialCount); a nil partial (proof.ErrMalformed); a trustee index
// outside 1..2^32-1 (ErrBadIndex); a repeated index (ErrDuplicateIndex); an
// index with no entry in keys (ErrUnknownTrustee); and any partial that
// fails VerifyPartial. Only then does it Lagrange-combine the D_i, compute
// c2 - Σ λ_i * D_i and solve for m in [0, maxPlaintext]; a plaintext outside
// that range is ErrPlaintextOutOfRange.
func Combine(sc SlotContext, ct *elgamal.Ciphertext, partials []*Partial, keys map[int]*ristretto255.Element, threshold, maxPlaintext int) (int, error) {
	if threshold < 1 {
		return 0, fmt.Errorf("threshold: combine: threshold %d < 1", threshold)
	}
	if maxPlaintext < 0 {
		return 0, fmt.Errorf("threshold: combine: maxPlaintext %d < 0", maxPlaintext)
	}
	if len(partials) != threshold {
		return 0, fmt.Errorf("threshold: combine: %d partials for threshold %d: %w", len(partials), threshold, ErrPartialCount)
	}

	indices := make([]int, len(partials))
	for i, p := range partials {
		if p == nil {
			return 0, fmt.Errorf("threshold: combine: partial %d is nil: %w", i, proof.ErrMalformed)
		}
		indices[i] = p.TrusteeIndex
	}
	if err := checkIndices(indices); err != nil {
		return 0, fmt.Errorf("threshold: combine: %w", err)
	}
	for _, idx := range indices {
		if _, ok := keys[idx]; !ok {
			return 0, fmt.Errorf("threshold: combine: trustee %d: %w", idx, ErrUnknownTrustee)
		}
	}
	for _, p := range partials {
		if err := VerifyPartial(sc, ct, p, keys[p.TrusteeIndex]); err != nil {
			return 0, fmt.Errorf("threshold: combine: trustee %d: %w", p.TrusteeIndex, err)
		}
	}

	lambdas := make([]*ristretto255.Scalar, len(partials))
	ds := make([]*ristretto255.Element, len(partials))
	for i, p := range partials {
		lambda, err := lagrangeAt(indices, i)
		if err != nil {
			return 0, fmt.Errorf("threshold: combine: %w", err)
		}
		lambdas[i] = lambda
		ds[i] = p.D
	}
	combined := ristretto255.NewIdentityElement().MultiScalarMult(lambdas, ds)

	// m * G = c2 - D
	gm := ristretto255.NewIdentityElement().Subtract(ct.C2, combined)
	m := internal.BabyStepGiantStep(gm, maxPlaintext)
	if m < 0 {
		return 0, fmt.Errorf("threshold: combine: max %d: %w", maxPlaintext, ErrPlaintextOutOfRange)
	}
	return m, nil
}

// checkSlot rejects an empty election id and a nil ciphertext or component.
func checkSlot(sc SlotContext, ct *elgamal.Ciphertext) error {
	if sc.ElectionID == "" {
		return fmt.Errorf("threshold: empty election id: %w", proof.ErrMalformed)
	}
	if ct == nil || ct.C1 == nil || ct.C2 == nil {
		return fmt.Errorf("threshold: nil ciphertext or component: %w", proof.ErrMalformed)
	}
	return nil
}

// partialContext returns the seven context fields of the partial-decryption
// transcript, in the order of docs/protocol/fiat-shamir.md: election_id,
// trustee_index, slot_index, c2, tally_digest, set_commitment, sealed_head.
// The caller has checked trusteeIndex with checkIndex, so it fits in a u32.
func partialContext(sc SlotContext, trusteeIndex int, c2 *ristretto255.Element) [][]byte {
	return [][]byte{
		[]byte(sc.ElectionID),
		binary.BigEndian.AppendUint32(nil, uint32(trusteeIndex)),
		binary.BigEndian.AppendUint32(nil, sc.SlotIndex),
		c2.Bytes(),
		sc.TallyDigest[:],
		sc.SetCommitment[:],
		sc.SealedHead[:],
	}
}
