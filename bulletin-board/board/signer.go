package board

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/valy0/otvoren-vot/bulletin-board/store"
)

// Signer signs Merkle roots with ECDSA P-256.
type Signer struct {
	key *ecdsa.PrivateKey
}

// NewSigner creates a signer. If key is nil, generates a dev key.
func NewSigner(key *ecdsa.PrivateKey) *Signer {
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic("generate dev key: " + err.Error())
		}
		key = k
	}
	return &Signer{key: key}
}

// PublicKey returns the signer's public key.
func (s *Signer) PublicKey() *ecdsa.PublicKey {
	return &s.key.PublicKey
}

// SignedRoot represents a signed Merkle root record.
type SignedRoot struct {
	RootSHA256  string    `json:"root_sha256"`
	BallotCount int64     `json:"ballot_count"`
	SignedAt    time.Time `json:"signed_at"`
	Signature   string    `json:"signature"`
}

// SignRoot signs the current board state.
func (s *Signer) SignRoot(b *Board) (*SignedRoot, error) {
	root := b.Root()
	size := int64(b.Size())
	now := time.Now().UTC()

	// Data to sign
	data := fmt.Sprintf("%s|%d|%s", root, size, now.Format(time.RFC3339Nano))
	hash := sha256.Sum256([]byte(data))

	r, ss, err := ecdsa.Sign(rand.Reader, s.key, hash[:])
	if err != nil {
		return nil, err
	}

	sig := base64.StdEncoding.EncodeToString(append(r.Bytes(), ss.Bytes()...))

	return &SignedRoot{
		RootSHA256:  root,
		BallotCount: size,
		SignedAt:    now,
		Signature:   sig,
	}, nil
}

// VerifySignature verifies a signed root against a public key.
func VerifySignature(pub *ecdsa.PublicKey, sr *SignedRoot) bool {
	data := fmt.Sprintf("%s|%d|%s", sr.RootSHA256, sr.BallotCount, sr.SignedAt.Format(time.RFC3339Nano))
	hash := sha256.Sum256([]byte(data))

	sigBytes, err := base64.StdEncoding.DecodeString(sr.Signature)
	if err != nil {
		return false
	}
	if len(sigBytes) < 2 {
		return false
	}

	// Split into r and s (variable length big-endian integers)
	half := len(sigBytes) / 2
	r := new(big.Int).SetBytes(sigBytes[:half])
	ss := new(big.Int).SetBytes(sigBytes[half:])

	return ecdsa.Verify(pub, hash[:], r, ss)
}

// ToStoreRecord converts to a store record for persistence.
func (sr *SignedRoot) ToStoreRecord() *store.SignedRootRecord {
	return &store.SignedRootRecord{
		RootSHA256:  sr.RootSHA256,
		BallotCount: sr.BallotCount,
		Signature:   sr.Signature,
	}
}
