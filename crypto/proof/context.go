package proof

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gtank/ristretto255"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

var (
	// ErrInvalidProof is returned when a well-formed proof does not satisfy
	// its verification equations.
	ErrInvalidProof = errors.New("proof: invalid proof")
	// ErrMalformed is returned for input that cannot be proven or verified:
	// an empty ElectionID or BallotID, a nil input or proof field, an
	// identity public key, an empty ciphertext vector, or a claimed plaintext
	// outside {0, 1}.
	ErrMalformed = errors.New("proof: malformed input")
)

// Context binds a ballot proof to one election, one ballot and one position
// within that ballot. Index is the statement index of
// docs/protocol/ballot-proofs.md section 8.4. The context is written into the
// transcript straight after the domain separator (docs/protocol/fiat-shamir.md,
// "Ballot-Proof Context"), so a proof made under one context does not verify
// under any other.
type Context struct {
	ElectionID string
	BallotID   string
	Index      uint32
}

func (c Context) validate() error {
	if c.ElectionID == "" {
		return fmt.Errorf("empty election id: %w", ErrMalformed)
	}
	if c.BallotID == "" {
		return fmt.Errorf("empty ballot id: %w", ErrMalformed)
	}
	return nil
}

// ballotChallenge computes a ballot-proof challenge:
//
//	FiatShamir(domain, utf8(election_id), utf8(ballot_id), u32be(index), statement...)
//
// Every field, the context ones included, gets its own length prefix.
func ballotChallenge(domain string, ctx Context, statement ...[]byte) *ristretto255.Scalar {
	fields := make([][]byte, 0, 3+len(statement))
	fields = append(fields,
		[]byte(ctx.ElectionID),
		[]byte(ctx.BallotID),
		binary.BigEndian.AppendUint32(nil, ctx.Index),
	)
	fields = append(fields, statement...)
	return internal.FiatShamir(domain, fields...)
}

func checkPublicKey(pk *ristretto255.Element) error {
	if pk == nil {
		return fmt.Errorf("nil public key: %w", ErrMalformed)
	}
	if pk.Equal(ristretto255.NewIdentityElement()) == 1 {
		return fmt.Errorf("identity public key: %w", ErrMalformed)
	}
	return nil
}

func checkCiphertext(name string, ct *elgamal.Ciphertext) error {
	if ct == nil {
		return fmt.Errorf("nil %s: %w", name, ErrMalformed)
	}
	if ct.C1 == nil || ct.C2 == nil {
		return fmt.Errorf("%s has a nil component: %w", name, ErrMalformed)
	}
	return nil
}

// checkBitWitness checks a prover's claimed plaintext m ∈ {0, 1} and its
// randomness r.
func checkBitWitness(m int, r *ristretto255.Scalar) error {
	if m != 0 && m != 1 {
		return fmt.Errorf("claimed plaintext %d is not 0 or 1: %w", m, ErrMalformed)
	}
	if r == nil {
		return fmt.Errorf("nil randomness: %w", ErrMalformed)
	}
	return nil
}
