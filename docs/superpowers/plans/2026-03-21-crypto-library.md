# Crypto Library Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `crypto/` Go package — the foundational cryptographic library providing ElGamal encryption over Ristretto255, Merkle trees (SHA-256 + Poseidon), Sigma proofs for ballot validity, and threshold key management primitives.

**Architecture:** A pure Go library (`github.com/valy0/otvoren-vot/crypto`) with sub-packages for each concern. No HTTP servers, no database access — just cryptographic primitives with clean interfaces. All operations use `filippo.io/edwards25519` for Ristretto255 group arithmetic. The library is consumed by the bulletin-board, tally, collection, and verification services in later phases.

**Tech Stack:** Go 1.22+, `filippo.io/edwards25519`, `crypto/sha256` (stdlib), standard `testing` package

**Review Fixes (must be applied during implementation):**

1. **CRITICAL: Include public key in all Fiat-Shamir hashes.** Every `FiatShamir()` call in binary proof, sum proof, and Chaum-Pedersen must include `publicKey.Bytes()` as part of the hashed data. This prevents proof transplant attacks across different election keys.

2. **CRITICAL: Chaum-Pedersen convention.** The plan uses `z = k + e*x` (additive). The protocol spec uses `z = k - e*x` (subtractive). Use the additive convention (`z = k + e*x`) consistently and update the protocol spec to match, since we control both. Verification equation: `z*G == U + e*A`.

3. **HIGH: Add candidate validity proofs.** After Task 5, add a new task implementing `proof/candidate.go` with: (a) `ProveCandidateSumZeroOrOne` — disjunctive proof that a candidate vector sums to 0 or 1, (b) `ProveConditionalConsistency` — proof that if candidate sum = 1, the corresponding party element = 1.

4. **HIGH: Expose randomness from ballot encoding.** Modify `EncodeBallot` / `EncodeBallotWithCandidates` to return randomness vectors alongside ciphertexts. Or create `EncodeBallotWithProofs` that generates ballot + all validity proofs together. The caller needs the randomness to generate proofs.

5. **MEDIUM: Remove ScalarWrapper.** Change `SumScalars` to accept `[]*edwards25519.Scalar` directly.

6. **MEDIUM: Implement dkg.go.** The file is in the file map but has no implementation in the plan. Add a `DKGProtocol` struct wrapping multi-party Feldman VSS with Round 1/2/3 abstraction.

7. **MEDIUM: Factor out BSGS.** Move baby-step giant-step to `internal/bsgs.go`, reuse from both `elgamal.go` and `threshold/decrypt.go`.

8. **MEDIUM: Scope exclusions.** Poseidon/BN254 Merkle tree is deferred to the gnark/deduplication phase (Phase 3). Tally correctness proof is a composition of Chaum-Pedersen proofs on decrypted tally sums — deferred to tally service (Phase 3).

9. **LOW: Add proof serialization** (`Bytes()`/`FromBytes()`) for all proof types.

10. **LOW: Add known-answer test vectors** in `crypto/testdata/` for cross-validation with future JS client.

**Reference specs:**
- `docs/protocol/elgamal.md` — ElGamal encryption, ballot encoding, homomorphic tallying
- `docs/protocol/ballot-proofs.md` — Sigma protocols, binary proofs, sum-to-one
- `docs/protocol/threshold.md` — Feldman VSS, DKG, partial decryption
- `docs/protocol/overview.md` — group definitions, dual-hash Merkle tree

---

## File Map

```
crypto/
├── go.mod                          # module github.com/valy0/otvoren-vot/crypto
├── go.sum
├── elgamal/
│   ├── elgamal.go                  # KeyPair, Encrypt, Decrypt, HomomorphicAdd
│   ├── elgamal_test.go
│   ├── ballot.go                   # Ballot encoding (party vector, candidate vectors)
│   └── ballot_test.go
├── proof/
│   ├── binary.go                   # Disjunctive Chaum-Pedersen OR-proof (value is 0 or 1)
│   ├── binary_test.go
│   ├── sum.go                      # Sum-to-one proof (vector sums to exactly 1)
│   ├── sum_test.go
│   ├── chaumpedersen.go            # Basic Chaum-Pedersen equality proof (used by threshold decryption)
│   └── chaumpedersen_test.go
├── merkle/
│   ├── merkle.go                   # SHA-256 Merkle tree (append-only, inclusion proofs)
│   └── merkle_test.go
├── threshold/
│   ├── feldman.go                  # Feldman VSS: share generation, verification, combination
│   ├── feldman_test.go
│   ├── dkg.go                      # DKG protocol: multi-party key generation
│   ├── dkg_test.go
│   ├── decrypt.go                  # Partial decryption, Lagrange combination, BSGS
│   └── decrypt_test.go
└── internal/
    ├── scalar.go                   # Scalar utilities: random, hash-to-scalar, Fiat-Shamir
    └── scalar_test.go
```

---

## Task 1: Go Module and Scalar Utilities

**Files:**
- Create: `crypto/go.mod`
- Create: `crypto/internal/scalar.go`
- Create: `crypto/internal/scalar_test.go`

- [ ] **Step 1: Initialize Go module**

```bash
cd /Users/valentincholakov/dev/voting-system
mkdir -p crypto/internal
cd crypto
go mod init github.com/valy0/otvoren-vot/crypto
go get filippo.io/edwards25519@latest
```

- [ ] **Step 2: Write scalar utility tests**

Create `crypto/internal/scalar_test.go`:

```go
package internal

import (
	"testing"
)

func TestRandomScalar(t *testing.T) {
	s1 := RandomScalar()
	s2 := RandomScalar()
	if s1.Equal(s2) == 1 {
		t.Fatal("two random scalars should not be equal")
	}
}

func TestHashToScalar(t *testing.T) {
	s1 := HashToScalar([]byte("otvoren-vot.test"), []byte("input1"))
	s2 := HashToScalar([]byte("otvoren-vot.test"), []byte("input2"))
	s3 := HashToScalar([]byte("otvoren-vot.test"), []byte("input1"))
	if s1.Equal(s2) == 1 {
		t.Fatal("different inputs should produce different scalars")
	}
	if s1.Equal(s3) != 1 {
		t.Fatal("same inputs should produce same scalar")
	}
}

func TestFiatShamir(t *testing.T) {
	e1 := FiatShamir("otvoren-vot.test-proof", []byte("data1"))
	e2 := FiatShamir("otvoren-vot.test-proof", []byte("data2"))
	e3 := FiatShamir("otvoren-vot.test-proof", []byte("data1"))
	if e1.Equal(e2) == 1 {
		t.Fatal("different data should produce different challenges")
	}
	if e1.Equal(e3) != 1 {
		t.Fatal("same data should produce same challenge")
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd /Users/valentincholakov/dev/voting-system/crypto
go test ./internal/ -v
```

Expected: FAIL — functions not defined.

- [ ] **Step 4: Implement scalar utilities**

Create `crypto/internal/scalar.go`:

```go
package internal

import (
	"crypto/rand"
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// RandomScalar generates a cryptographically random scalar in Z_q.
func RandomScalar() *edwards25519.Scalar {
	var buf [64]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	s, err := edwards25519.NewScalar().SetUniformBytes(buf[:])
	if err != nil {
		panic("SetUniformBytes failed: " + err.Error())
	}
	return s
}

// HashToScalar hashes a domain separator and arbitrary data to a scalar.
// Uses SHA-512 and reduces modulo the group order.
func HashToScalar(domain, data []byte) *edwards25519.Scalar {
	h := sha512.New()
	h.Write(domain)
	h.Write(data)
	var digest [64]byte
	copy(digest[:], h.Sum(nil))
	s, err := edwards25519.NewScalar().SetUniformBytes(digest[:])
	if err != nil {
		panic("SetUniformBytes failed: " + err.Error())
	}
	return s
}

// FiatShamir computes a non-interactive challenge from a domain separator
// and serialized proof data. This replaces the verifier's random challenge
// in Sigma protocols.
func FiatShamir(domain string, data ...[]byte) *edwards25519.Scalar {
	h := sha512.New()
	h.Write([]byte(domain))
	for _, d := range data {
		h.Write(d)
	}
	var digest [64]byte
	copy(digest[:], h.Sum(nil))
	s, err := edwards25519.NewScalar().SetUniformBytes(digest[:])
	if err != nil {
		panic("SetUniformBytes failed: " + err.Error())
	}
	return s
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
go test ./internal/ -v
```

Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add crypto/
git commit -m "feat(crypto): initialize Go module and scalar utilities"
```

---

## Task 2: ElGamal Encryption

**Files:**
- Create: `crypto/elgamal/elgamal.go`
- Create: `crypto/elgamal/elgamal_test.go`

- [ ] **Step 1: Write ElGamal tests**

Create `crypto/elgamal/elgamal_test.go`:

```go
package elgamal

import (
	"testing"

	"filippo.io/edwards25519"
)

func TestKeyGeneration(t *testing.T) {
	kp := GenerateKeyPair()
	if kp.PrivateKey == nil || kp.PublicKey == nil {
		t.Fatal("key pair fields should not be nil")
	}
	// Verify h = g^x
	expected := new(edwards25519.Point).ScalarBaseMult(kp.PrivateKey)
	if expected.Equal(kp.PublicKey) != 1 {
		t.Fatal("public key should equal g^x")
	}
}

func TestEncryptDecryptZero(t *testing.T) {
	kp := GenerateKeyPair()
	ct := Encrypt(kp.PublicKey, 0)
	m := Decrypt(kp.PrivateKey, ct)
	if m != 0 {
		t.Fatalf("expected 0, got %d", m)
	}
}

func TestEncryptDecryptOne(t *testing.T) {
	kp := GenerateKeyPair()
	ct := Encrypt(kp.PublicKey, 1)
	m := Decrypt(kp.PrivateKey, ct)
	if m != 1 {
		t.Fatalf("expected 1, got %d", m)
	}
}

func TestHomomorphicAddition(t *testing.T) {
	kp := GenerateKeyPair()
	ct1 := Encrypt(kp.PublicKey, 1)
	ct2 := Encrypt(kp.PublicKey, 1)
	ct3 := Encrypt(kp.PublicKey, 0)

	sum := HomomorphicAdd(ct1, ct2, ct3)
	m := Decrypt(kp.PrivateKey, sum)
	if m != 2 {
		t.Fatalf("expected 2, got %d", m)
	}
}

func TestHomomorphicTally(t *testing.T) {
	kp := GenerateKeyPair()
	// Simulate 100 voters: 60 vote for option, 40 don't
	cts := make([]*Ciphertext, 100)
	for i := 0; i < 100; i++ {
		if i < 60 {
			cts[i] = Encrypt(kp.PublicKey, 1)
		} else {
			cts[i] = Encrypt(kp.PublicKey, 0)
		}
	}
	sum := HomomorphicAdd(cts...)
	m := Decrypt(kp.PrivateKey, sum)
	if m != 60 {
		t.Fatalf("expected 60, got %d", m)
	}
}

func TestCiphertextSerialization(t *testing.T) {
	kp := GenerateKeyPair()
	ct := Encrypt(kp.PublicKey, 1)
	data := ct.Bytes()
	ct2, err := CiphertextFromBytes(data)
	if err != nil {
		t.Fatalf("deserialization failed: %v", err)
	}
	m := Decrypt(kp.PrivateKey, ct2)
	if m != 1 {
		t.Fatalf("expected 1 after round-trip, got %d", m)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./elgamal/ -v
```

- [ ] **Step 3: Implement ElGamal**

Create `crypto/elgamal/elgamal.go`:

```go
package elgamal

import (
	"errors"
	"math/big"

	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

// KeyPair holds an ElGamal key pair over Ristretto255.
type KeyPair struct {
	PrivateKey *edwards25519.Scalar
	PublicKey  *edwards25519.Point
}

// GenerateKeyPair creates a fresh ElGamal key pair.
// Private key x is random in Z_q, public key h = g^x.
func GenerateKeyPair() *KeyPair {
	x := internal.RandomScalar()
	h := new(edwards25519.Point).ScalarBaseMult(x)
	return &KeyPair{PrivateKey: x, PublicKey: h}
}

// Ciphertext is an exponential ElGamal ciphertext (c1, c2).
type Ciphertext struct {
	C1 *edwards25519.Point // g^r
	C2 *edwards25519.Point // h^r * g^m
}

// Encrypt encrypts a small integer m (typically 0 or 1) under the given public key.
// c1 = g^r, c2 = h^r * g^m
func Encrypt(publicKey *edwards25519.Point, m int) *Ciphertext {
	r := internal.RandomScalar()
	c1 := new(edwards25519.Point).ScalarBaseMult(r)
	hr := new(edwards25519.Point).ScalarMult(r, publicKey)
	gm := scalarBaseMultInt(m)
	c2 := new(edwards25519.Point).Add(hr, gm)
	return &Ciphertext{C1: c1, C2: c2}
}

// EncryptWithRandomness encrypts m with explicit randomness r.
// Used when the randomness must be known for proof generation.
func EncryptWithRandomness(publicKey *edwards25519.Point, m int, r *edwards25519.Scalar) *Ciphertext {
	c1 := new(edwards25519.Point).ScalarBaseMult(r)
	hr := new(edwards25519.Point).ScalarMult(r, publicKey)
	gm := scalarBaseMultInt(m)
	c2 := new(edwards25519.Point).Add(hr, gm)
	return &Ciphertext{C1: c1, C2: c2}
}

// HomomorphicAdd combines ciphertexts homomorphically.
// The result encrypts the sum of all plaintexts.
func HomomorphicAdd(cts ...*Ciphertext) *Ciphertext {
	if len(cts) == 0 {
		return nil
	}
	sumC1 := new(edwards25519.Point).Set(cts[0].C1)
	sumC2 := new(edwards25519.Point).Set(cts[0].C2)
	for _, ct := range cts[1:] {
		sumC1.Add(sumC1, ct.C1)
		sumC2.Add(sumC2, ct.C2)
	}
	return &Ciphertext{C1: sumC1, C2: sumC2}
}

// Decrypt recovers the plaintext from a ciphertext using the full private key.
// Returns the plaintext integer m by solving a discrete log via BSGS.
// Only works for small m (up to maxDecrypt).
func Decrypt(privateKey *edwards25519.Scalar, ct *Ciphertext) int {
	// Compute g^m = c2 / c1^x = c2 * (c1^x)^{-1}
	s := new(edwards25519.Point).ScalarMult(privateKey, ct.C1)
	s.Negate(s)
	gm := new(edwards25519.Point).Add(ct.C2, s)
	return babyStepGiantStep(gm, maxDecrypt)
}

// Bytes serializes the ciphertext to 64 bytes (32 per point).
func (ct *Ciphertext) Bytes() []byte {
	out := make([]byte, 64)
	copy(out[:32], ct.C1.Bytes())
	copy(out[32:], ct.C2.Bytes())
	return out
}

// CiphertextFromBytes deserializes a ciphertext from 64 bytes.
func CiphertextFromBytes(data []byte) (*Ciphertext, error) {
	if len(data) != 64 {
		return nil, errors.New("ciphertext must be 64 bytes")
	}
	c1, err := new(edwards25519.Point).SetBytes(data[:32])
	if err != nil {
		return nil, err
	}
	c2, err := new(edwards25519.Point).SetBytes(data[32:])
	if err != nil {
		return nil, err
	}
	return &Ciphertext{C1: c1, C2: c2}, nil
}

const maxDecrypt = 5_000_000 // Max plaintext for BSGS (covers ~4M voters + margin)

// babyStepGiantStep solves g^m = target for m in [0, max].
// Returns m, or -1 if not found.
func babyStepGiantStep(target *edwards25519.Point, max int) int {
	// Baby step size: ceil(sqrt(max))
	step := 1
	for step*step < max {
		step++
	}

	g := edwards25519.NewGeneratorPoint()

	// Baby steps: build table of {g^j => j} for j = 0..step-1
	table := make(map[[32]byte]int, step)
	current := new(edwards25519.Point).Set(edwards25519.NewIdentityPoint())
	for j := 0; j < step; j++ {
		var key [32]byte
		copy(key[:], current.Bytes())
		table[key] = j
		current.Add(current, g)
	}

	// Giant step: g^{-step}
	stepScalar := scalarFromInt(step)
	giantStep := new(edwards25519.Point).ScalarBaseMult(stepScalar)
	giantStep.Negate(giantStep)

	// Search: target * (g^{-step})^i for i = 0, 1, ...
	gamma := new(edwards25519.Point).Set(target)
	for i := 0; i <= max/step+1; i++ {
		var key [32]byte
		copy(key[:], gamma.Bytes())
		if j, ok := table[key]; ok {
			return i*step + j
		}
		gamma.Add(gamma, giantStep)
	}
	return -1
}

func scalarFromInt(n int) *edwards25519.Scalar {
	var buf [32]byte
	b := big.NewInt(int64(n)).Bytes()
	// edwards25519 uses little-endian
	for i, v := range b {
		buf[len(b)-1-i] = v
	}
	s, err := edwards25519.NewScalar().SetCanonicalBytes(buf[:])
	if err != nil {
		panic("scalarFromInt: " + err.Error())
	}
	return s
}

func scalarBaseMultInt(m int) *edwards25519.Point {
	if m == 0 {
		return edwards25519.NewIdentityPoint()
	}
	s := scalarFromInt(m)
	return new(edwards25519.Point).ScalarBaseMult(s)
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./elgamal/ -v
```

Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add crypto/elgamal/
git commit -m "feat(crypto): add ElGamal encryption over Ristretto255"
```

---

## Task 3: Ballot Encoding

**Files:**
- Create: `crypto/elgamal/ballot.go`
- Create: `crypto/elgamal/ballot_test.go`

- [ ] **Step 1: Write ballot encoding tests**

Create `crypto/elgamal/ballot_test.go`:

```go
package elgamal

import (
	"testing"
)

func TestEncodeBallotPartyOnly(t *testing.T) {
	kp := GenerateKeyPair()
	b := EncodeBallot(kp.PublicKey, 5, 3, -1) // 5 parties, chose party 3, no candidate
	if len(b.PartyVector) != 5 {
		t.Fatalf("expected 5 party ciphertexts, got %d", len(b.PartyVector))
	}
	// Decrypt and verify
	for i, ct := range b.PartyVector {
		m := Decrypt(kp.PrivateKey, ct)
		if i == 3 && m != 1 {
			t.Fatalf("party %d should be 1, got %d", i, m)
		}
		if i != 3 && m != 0 {
			t.Fatalf("party %d should be 0, got %d", i, m)
		}
	}
}

func TestEncodeBallotWithCandidate(t *testing.T) {
	kp := GenerateKeyPair()
	// 3 parties, 4 candidates each, chose party 1, candidate 2
	b := EncodeBallot(kp.PublicKey, 3, 1, 2)
	// Party 1's candidate vector should have 1 at position 2
	for i, ct := range b.CandidateVectors[1] {
		m := Decrypt(kp.PrivateKey, ct)
		if i == 2 && m != 1 {
			t.Fatalf("candidate %d should be 1, got %d", i, m)
		}
		if i != 2 && m != 0 {
			t.Fatalf("candidate %d should be 0, got %d", i, m)
		}
	}
	// Other parties' candidate vectors should be all zeros
	for i, ct := range b.CandidateVectors[0] {
		m := Decrypt(kp.PrivateKey, ct)
		if m != 0 {
			t.Fatalf("party 0 candidate %d should be 0, got %d", i, m)
		}
	}
}

func TestHomomorphicBallotTally(t *testing.T) {
	kp := GenerateKeyPair()
	numParties := 3

	// 10 voters: 4 vote party 0, 3 vote party 1, 3 vote party 2
	votes := []int{0, 0, 0, 0, 1, 1, 1, 2, 2, 2}
	ballots := make([]*Ballot, len(votes))
	for i, party := range votes {
		ballots[i] = EncodeBallot(kp.PublicKey, numParties, party, -1)
	}

	tally := TallyBallots(ballots)
	for i, ct := range tally.PartyVector {
		m := Decrypt(kp.PrivateKey, ct)
		expected := 0
		for _, v := range votes {
			if v == i {
				expected++
			}
		}
		if m != expected {
			t.Fatalf("party %d: expected %d, got %d", i, expected, m)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./elgamal/ -v -run TestEncode
```

- [ ] **Step 3: Implement ballot encoding**

Create `crypto/elgamal/ballot.go`:

```go
package elgamal

import "filippo.io/edwards25519"

// Ballot represents an encrypted ballot with party and candidate vectors.
type Ballot struct {
	PartyVector      []*Ciphertext   // One ciphertext per party (one-hot)
	CandidateVectors [][]*Ciphertext // Per-party candidate vectors
	NumParties       int
	NumCandidates    int // Per party (uniform for simplicity)
}

// EncodeBallot creates an encrypted ballot.
// partyChoice: index of chosen party (0-based).
// candidateChoice: index of chosen candidate within party (-1 for no preference).
// numCandidates is read from the first candidate vector length or defaults to 0.
func EncodeBallot(publicKey *edwards25519.Point, numParties, partyChoice, candidateChoice int) *Ballot {
	b := &Ballot{
		PartyVector: make([]*Ciphertext, numParties),
		NumParties:  numParties,
	}

	// Encrypt party vector (one-hot)
	for i := 0; i < numParties; i++ {
		if i == partyChoice {
			b.PartyVector[i] = Encrypt(publicKey, 1)
		} else {
			b.PartyVector[i] = Encrypt(publicKey, 0)
		}
	}

	return b
}

// EncodeBallotWithCandidates creates an encrypted ballot with candidate preferences.
func EncodeBallotWithCandidates(publicKey *edwards25519.Point, numParties, numCandidates, partyChoice, candidateChoice int) *Ballot {
	b := EncodeBallot(publicKey, numParties, partyChoice, candidateChoice)
	b.NumCandidates = numCandidates
	b.CandidateVectors = make([][]*Ciphertext, numParties)

	for p := 0; p < numParties; p++ {
		b.CandidateVectors[p] = make([]*Ciphertext, numCandidates)
		for c := 0; c < numCandidates; c++ {
			if p == partyChoice && c == candidateChoice {
				b.CandidateVectors[p][c] = Encrypt(publicKey, 1)
			} else {
				b.CandidateVectors[p][c] = Encrypt(publicKey, 0)
			}
		}
	}
	return b
}

// TallyBallots homomorphically sums a slice of ballots.
func TallyBallots(ballots []*Ballot) *Ballot {
	if len(ballots) == 0 {
		return nil
	}
	numParties := ballots[0].NumParties
	result := &Ballot{
		PartyVector: make([]*Ciphertext, numParties),
		NumParties:  numParties,
	}

	// Sum party vectors
	for i := 0; i < numParties; i++ {
		cts := make([]*Ciphertext, len(ballots))
		for j, b := range ballots {
			cts[j] = b.PartyVector[i]
		}
		result.PartyVector[i] = HomomorphicAdd(cts...)
	}

	// Sum candidate vectors if present
	if ballots[0].CandidateVectors != nil {
		numCandidates := ballots[0].NumCandidates
		result.NumCandidates = numCandidates
		result.CandidateVectors = make([][]*Ciphertext, numParties)
		for p := 0; p < numParties; p++ {
			result.CandidateVectors[p] = make([]*Ciphertext, numCandidates)
			for c := 0; c < numCandidates; c++ {
				cts := make([]*Ciphertext, len(ballots))
				for j, b := range ballots {
					cts[j] = b.CandidateVectors[p][c]
				}
				result.CandidateVectors[p][c] = HomomorphicAdd(cts...)
			}
		}
	}

	return result
}
```

Also update `EncodeBallot` in `ballot_test.go` — the test uses 3 params for candidate vectors, so update `EncodeBallot` signature to handle the `candidateChoice = -1` case for no candidates, and update the candidate test to use `EncodeBallotWithCandidates`:

Update `ballot_test.go` `TestEncodeBallotWithCandidate` to call `EncodeBallotWithCandidates(kp.PublicKey, 3, 4, 1, 2)`.

- [ ] **Step 4: Run tests**

```bash
go test ./elgamal/ -v
```

Expected: PASS (all tests including ballot tests).

- [ ] **Step 5: Commit**

```bash
git add crypto/elgamal/
git commit -m "feat(crypto): add ballot encoding and homomorphic tallying"
```

---

## Task 4: Binary Proof (Disjunctive Chaum-Pedersen)

**Files:**
- Create: `crypto/proof/binary.go`
- Create: `crypto/proof/binary_test.go`

- [ ] **Step 1: Write binary proof tests**

Create `crypto/proof/binary_test.go`:

```go
package proof

import (
	"testing"

	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

func TestBinaryProofZero(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	r := internal.RandomScalar()
	ct := elgamal.EncryptWithRandomness(kp.PublicKey, 0, r)
	proof := ProveBinary(kp.PublicKey, ct, 0, r)
	if !VerifyBinary(kp.PublicKey, ct, proof) {
		t.Fatal("valid proof for 0 should verify")
	}
}

func TestBinaryProofOne(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	r := internal.RandomScalar()
	ct := elgamal.EncryptWithRandomness(kp.PublicKey, 1, r)
	proof := ProveBinary(kp.PublicKey, ct, 1, r)
	if !VerifyBinary(kp.PublicKey, ct, proof) {
		t.Fatal("valid proof for 1 should verify")
	}
}

func TestBinaryProofInvalidMessage(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	r := internal.RandomScalar()
	ct := elgamal.EncryptWithRandomness(kp.PublicKey, 1, r)
	// Try to prove it's 0 when it's actually 1
	proof := ProveBinary(kp.PublicKey, ct, 0, r)
	if VerifyBinary(kp.PublicKey, ct, proof) {
		t.Fatal("proof for wrong message should NOT verify")
	}
}

func TestBinaryProofTamperedCiphertext(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	r := internal.RandomScalar()
	ct := elgamal.EncryptWithRandomness(kp.PublicKey, 1, r)
	proof := ProveBinary(kp.PublicKey, ct, 1, r)

	// Tamper with ciphertext
	ct2 := elgamal.Encrypt(kp.PublicKey, 0)
	if VerifyBinary(kp.PublicKey, ct2, proof) {
		t.Fatal("proof should not verify against different ciphertext")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./proof/ -v
```

- [ ] **Step 3: Implement binary proof**

Create `crypto/proof/binary.go`:

```go
package proof

import (
	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

const binaryDomain = "otvoren-vot.ballot-binary-proof"

// BinaryProof is a disjunctive Chaum-Pedersen proof that an ElGamal
// ciphertext encrypts either 0 or 1.
type BinaryProof struct {
	A0 *edwards25519.Point // commitment for the m=0 branch
	A1 *edwards25519.Point // commitment for the m=1 branch
	B0 *edwards25519.Point
	B1 *edwards25519.Point
	E0 *edwards25519.Scalar // challenge for the m=0 branch
	E1 *edwards25519.Scalar // challenge for the m=1 branch
	Z0 *edwards25519.Scalar // response for the m=0 branch
	Z1 *edwards25519.Scalar // response for the m=1 branch
}

// ProveBinary creates a ZK proof that ct encrypts m ∈ {0, 1}.
// The prover must know the actual message m and randomness r.
func ProveBinary(publicKey *edwards25519.Point, ct *elgamal.Ciphertext, m int, r *edwards25519.Scalar) *BinaryProof {
	g := edwards25519.NewGeneratorPoint()

	if m == 0 {
		return proveBinaryReal0(g, publicKey, ct, r)
	}
	return proveBinaryReal1(g, publicKey, ct, r)
}

// proveBinaryReal0: m=0 is real, m=1 is simulated
func proveBinaryReal0(g, h *edwards25519.Point, ct *elgamal.Ciphertext, r *edwards25519.Scalar) *BinaryProof {
	// Real branch (m=0): commitment
	k := internal.RandomScalar()
	a0 := new(edwards25519.Point).ScalarBaseMult(k)          // g^k
	b0 := new(edwards25519.Point).ScalarMult(k, h)           // h^k

	// Simulated branch (m=1): choose e1, z1 randomly, compute commitments
	e1 := internal.RandomScalar()
	z1 := internal.RandomScalar()

	// a1 = g^z1 * c1^{-e1}
	gz1 := new(edwards25519.Point).ScalarBaseMult(z1)
	c1e1 := new(edwards25519.Point).ScalarMult(e1, ct.C1)
	c1e1.Negate(c1e1)
	a1 := new(edwards25519.Point).Add(gz1, c1e1)

	// b1 = h^z1 * (c2/g)^{-e1}  (c2/g because for m=1, c2 = h^r * g)
	hz1 := new(edwards25519.Point).ScalarMult(z1, h)
	c2DivG := new(edwards25519.Point).Add(ct.C2, new(edwards25519.Point).Negate(g))
	c2ge1 := new(edwards25519.Point).ScalarMult(e1, c2DivG)
	c2ge1.Negate(c2ge1)
	b1 := new(edwards25519.Point).Add(hz1, c2ge1)

	// Fiat-Shamir challenge
	e := internal.FiatShamir(binaryDomain,
		ct.C1.Bytes(), ct.C2.Bytes(),
		a0.Bytes(), b0.Bytes(),
		a1.Bytes(), b1.Bytes())

	// e0 = e - e1
	e0 := new(edwards25519.Scalar).Subtract(e, e1)

	// z0 = k + e0 * r
	z0 := new(edwards25519.Scalar).MultiplyAdd(e0, r, k)

	return &BinaryProof{
		A0: a0, A1: a1, B0: b0, B1: b1,
		E0: e0, E1: e1, Z0: z0, Z1: z1,
	}
}

// proveBinaryReal1: m=1 is real, m=0 is simulated
func proveBinaryReal1(g, h *edwards25519.Point, ct *elgamal.Ciphertext, r *edwards25519.Scalar) *BinaryProof {
	// Simulated branch (m=0): choose e0, z0 randomly
	e0 := internal.RandomScalar()
	z0 := internal.RandomScalar()

	// a0 = g^z0 * c1^{-e0}
	gz0 := new(edwards25519.Point).ScalarBaseMult(z0)
	c1e0 := new(edwards25519.Point).ScalarMult(e0, ct.C1)
	c1e0.Negate(c1e0)
	a0 := new(edwards25519.Point).Add(gz0, c1e0)

	// b0 = h^z0 * c2^{-e0}  (for m=0, c2 = h^r * g^0 = h^r)
	hz0 := new(edwards25519.Point).ScalarMult(z0, h)
	c2e0 := new(edwards25519.Point).ScalarMult(e0, ct.C2)
	c2e0.Negate(c2e0)
	b0 := new(edwards25519.Point).Add(hz0, c2e0)

	// Real branch (m=1): commitment
	k := internal.RandomScalar()
	a1 := new(edwards25519.Point).ScalarBaseMult(k)
	b1 := new(edwards25519.Point).ScalarMult(k, h)

	// Fiat-Shamir challenge
	e := internal.FiatShamir(binaryDomain,
		ct.C1.Bytes(), ct.C2.Bytes(),
		a0.Bytes(), b0.Bytes(),
		a1.Bytes(), b1.Bytes())

	// e1 = e - e0
	e1 := new(edwards25519.Scalar).Subtract(e, e0)

	// z1 = k + e1 * r
	z1 := new(edwards25519.Scalar).MultiplyAdd(e1, r, k)

	return &BinaryProof{
		A0: a0, A1: a1, B0: b0, B1: b1,
		E0: e0, E1: e1, Z0: z0, Z1: z1,
	}
}

// VerifyBinary verifies a binary proof.
func VerifyBinary(publicKey *edwards25519.Point, ct *elgamal.Ciphertext, p *BinaryProof) bool {
	g := edwards25519.NewGeneratorPoint()

	// Recompute Fiat-Shamir challenge
	e := internal.FiatShamir(binaryDomain,
		ct.C1.Bytes(), ct.C2.Bytes(),
		p.A0.Bytes(), p.B0.Bytes(),
		p.A1.Bytes(), p.B1.Bytes())

	// Check e0 + e1 = e
	eSum := new(edwards25519.Scalar).Add(p.E0, p.E1)
	if eSum.Equal(e) != 1 {
		return false
	}

	// Check branch 0: g^z0 == a0 * c1^e0
	lhs0 := new(edwards25519.Point).ScalarBaseMult(p.Z0)
	rhs0 := new(edwards25519.Point).Add(p.A0, new(edwards25519.Point).ScalarMult(p.E0, ct.C1))
	if lhs0.Equal(rhs0) != 1 {
		return false
	}

	// Check branch 0: h^z0 == b0 * c2^e0
	lhs0b := new(edwards25519.Point).ScalarMult(p.Z0, publicKey)
	rhs0b := new(edwards25519.Point).Add(p.B0, new(edwards25519.Point).ScalarMult(p.E0, ct.C2))
	if lhs0b.Equal(rhs0b) != 1 {
		return false
	}

	// Check branch 1: g^z1 == a1 * c1^e1
	lhs1 := new(edwards25519.Point).ScalarBaseMult(p.Z1)
	rhs1 := new(edwards25519.Point).Add(p.A1, new(edwards25519.Point).ScalarMult(p.E1, ct.C1))
	if lhs1.Equal(rhs1) != 1 {
		return false
	}

	// Check branch 1: h^z1 == b1 * (c2/g)^e1
	c2DivG := new(edwards25519.Point).Add(ct.C2, new(edwards25519.Point).Negate(g))
	lhs1b := new(edwards25519.Point).ScalarMult(p.Z1, publicKey)
	rhs1b := new(edwards25519.Point).Add(p.B1, new(edwards25519.Point).ScalarMult(p.E1, c2DivG))
	if lhs1b.Equal(rhs1b) != 1 {
		return false
	}

	return true
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./proof/ -v
```

Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add crypto/proof/
git commit -m "feat(crypto): add disjunctive Chaum-Pedersen binary proof"
```

---

## Task 5: Sum-to-One Proof

**Files:**
- Create: `crypto/proof/sum.go`
- Create: `crypto/proof/sum_test.go`

- [ ] **Step 1: Write sum proof tests**

Create `crypto/proof/sum_test.go`:

```go
package proof

import (
	"testing"

	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

func TestSumProofValid(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	n := 5
	selected := 2
	cts := make([]*elgamal.Ciphertext, n)
	rs := make([]*internal.ScalarWrapper, n) // we'll need to track randomness
	for i := 0; i < n; i++ {
		r := internal.RandomScalar()
		m := 0
		if i == selected {
			m = 1
		}
		cts[i] = elgamal.EncryptWithRandomness(kp.PublicKey, m, r)
		rs[i] = &internal.ScalarWrapper{S: r}
	}

	// Sum of randomness
	rSum := internal.SumScalars(rs)

	proof := ProveSumOne(kp.PublicKey, cts, rSum)
	if !VerifySumOne(kp.PublicKey, cts, proof) {
		t.Fatal("valid sum-to-one proof should verify")
	}
}

func TestSumProofInvalid(t *testing.T) {
	kp := elgamal.GenerateKeyPair()
	// All zeros — sums to 0, not 1
	cts := make([]*elgamal.Ciphertext, 3)
	rs := make([]*internal.ScalarWrapper, 3)
	for i := 0; i < 3; i++ {
		r := internal.RandomScalar()
		cts[i] = elgamal.EncryptWithRandomness(kp.PublicKey, 0, r)
		rs[i] = &internal.ScalarWrapper{S: r}
	}
	rSum := internal.SumScalars(rs)
	proof := ProveSumOne(kp.PublicKey, cts, rSum)
	if VerifySumOne(kp.PublicKey, cts, proof) {
		t.Fatal("sum-to-zero proof should NOT verify as sum-to-one")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Add ScalarWrapper and SumScalars to internal**

Add to `crypto/internal/scalar.go`:

```go
// ScalarWrapper wraps a scalar for passing around in slices.
type ScalarWrapper struct {
	S *edwards25519.Scalar
}

// SumScalars adds all scalars together.
func SumScalars(scalars []*ScalarWrapper) *edwards25519.Scalar {
	sum := edwards25519.NewScalar()
	for _, sw := range scalars {
		sum.Add(sum, sw.S)
	}
	return sum
}
```

- [ ] **Step 4: Implement sum-to-one proof**

Create `crypto/proof/sum.go`:

```go
package proof

import (
	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

const sumDomain = "otvoren-vot.ballot-sum-proof"

// SumOneProof proves that the homomorphic sum of ciphertexts encrypts 1.
// This is a Chaum-Pedersen proof on the aggregated ciphertext.
type SumOneProof struct {
	A *edwards25519.Point  // g^k
	B *edwards25519.Point  // h^k
	Z *edwards25519.Scalar // k + e*rSum
}

// ProveSumOne creates a proof that the ciphertexts encrypt values summing to 1.
// rSum is the sum of all encryption randomness values.
func ProveSumOne(publicKey *edwards25519.Point, cts []*elgamal.Ciphertext, rSum *edwards25519.Scalar) *SumOneProof {
	// Aggregate ciphertext
	aggCt := elgamal.HomomorphicAdd(cts...)

	k := internal.RandomScalar()
	a := new(edwards25519.Point).ScalarBaseMult(k)
	b := new(edwards25519.Point).ScalarMult(k, publicKey)

	e := internal.FiatShamir(sumDomain,
		aggCt.C1.Bytes(), aggCt.C2.Bytes(),
		a.Bytes(), b.Bytes())

	z := new(edwards25519.Scalar).MultiplyAdd(e, rSum, k)

	return &SumOneProof{A: a, B: b, Z: z}
}

// VerifySumOne verifies that the ciphertexts encrypt values summing to 1.
func VerifySumOne(publicKey *edwards25519.Point, cts []*elgamal.Ciphertext, p *SumOneProof) bool {
	g := edwards25519.NewGeneratorPoint()

	aggCt := elgamal.HomomorphicAdd(cts...)

	e := internal.FiatShamir(sumDomain,
		aggCt.C1.Bytes(), aggCt.C2.Bytes(),
		p.A.Bytes(), p.B.Bytes())

	// Check g^z == a * c1^e
	lhs := new(edwards25519.Point).ScalarBaseMult(p.Z)
	rhs := new(edwards25519.Point).Add(p.A, new(edwards25519.Point).ScalarMult(e, aggCt.C1))
	if lhs.Equal(rhs) != 1 {
		return false
	}

	// Check h^z == b * (c2/g)^e  (because sum=1 means c2_agg = h^rSum * g^1)
	c2DivG := new(edwards25519.Point).Add(aggCt.C2, new(edwards25519.Point).Negate(g))
	lhs2 := new(edwards25519.Point).ScalarMult(p.Z, publicKey)
	rhs2 := new(edwards25519.Point).Add(p.B, new(edwards25519.Point).ScalarMult(e, c2DivG))
	if lhs2.Equal(rhs2) != 1 {
		return false
	}

	return true
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./proof/ -v
```

Expected: PASS (6 tests — 4 binary + 2 sum).

- [ ] **Step 6: Commit**

```bash
git add crypto/proof/ crypto/internal/
git commit -m "feat(crypto): add sum-to-one proof"
```

---

## Task 6: Chaum-Pedersen Equality Proof

**Files:**
- Create: `crypto/proof/chaumpedersen.go`
- Create: `crypto/proof/chaumpedersen_test.go`

- [ ] **Step 1: Write tests**

Create `crypto/proof/chaumpedersen_test.go`:

```go
package proof

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

func TestChaumPedersenValid(t *testing.T) {
	x := internal.RandomScalar()
	g := edwards25519.NewGeneratorPoint()
	h := new(edwards25519.Point).ScalarBaseMult(internal.RandomScalar()) // random second generator

	gx := new(edwards25519.Point).ScalarBaseMult(x)
	hx := new(edwards25519.Point).ScalarMult(x, h)

	proof := ProveChaumPedersen(g, h, gx, hx, x)
	if !VerifyChaumPedersen(g, h, gx, hx, proof) {
		t.Fatal("valid proof should verify")
	}
}

func TestChaumPedersenInvalid(t *testing.T) {
	x := internal.RandomScalar()
	y := internal.RandomScalar() // different secret
	g := edwards25519.NewGeneratorPoint()
	h := new(edwards25519.Point).ScalarBaseMult(internal.RandomScalar())

	gx := new(edwards25519.Point).ScalarBaseMult(x)
	hy := new(edwards25519.Point).ScalarMult(y, h) // wrong exponent

	proof := ProveChaumPedersen(g, h, gx, hy, x) // prover uses x but hy uses y
	if VerifyChaumPedersen(g, h, gx, hy, proof) {
		t.Fatal("proof with mismatched exponents should NOT verify")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement Chaum-Pedersen**

Create `crypto/proof/chaumpedersen.go`:

```go
package proof

import (
	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

const cpDomain = "otvoren-vot.chaum-pedersen"

// ChaumPedersenProof proves that two group elements share the same discrete log.
// Given g, h, A=g^x, B=h^x, proves knowledge of x such that A=g^x and B=h^x.
type ChaumPedersenProof struct {
	U *edwards25519.Point  // g^k
	V *edwards25519.Point  // h^k
	Z *edwards25519.Scalar // k + e*x
}

// ProveChaumPedersen creates a proof that A=g^x and B=h^x for the same x.
func ProveChaumPedersen(g, h, A, B *edwards25519.Point, x *edwards25519.Scalar) *ChaumPedersenProof {
	k := internal.RandomScalar()
	u := new(edwards25519.Point).ScalarMult(k, g)
	v := new(edwards25519.Point).ScalarMult(k, h)

	e := internal.FiatShamir(cpDomain,
		g.Bytes(), h.Bytes(),
		A.Bytes(), B.Bytes(),
		u.Bytes(), v.Bytes())

	z := new(edwards25519.Scalar).MultiplyAdd(e, x, k)

	return &ChaumPedersenProof{U: u, V: v, Z: z}
}

// VerifyChaumPedersen verifies the proof.
func VerifyChaumPedersen(g, h, A, B *edwards25519.Point, p *ChaumPedersenProof) bool {
	e := internal.FiatShamir(cpDomain,
		g.Bytes(), h.Bytes(),
		A.Bytes(), B.Bytes(),
		p.U.Bytes(), p.V.Bytes())

	// Check g^z == u * A^e
	gz := new(edwards25519.Point).ScalarMult(p.Z, g)
	ae := new(edwards25519.Point).ScalarMult(e, A)
	rhs1 := new(edwards25519.Point).Add(p.U, ae)
	if gz.Equal(rhs1) != 1 {
		return false
	}

	// Check h^z == v * B^e
	hz := new(edwards25519.Point).ScalarMult(p.Z, h)
	be := new(edwards25519.Point).ScalarMult(e, B)
	rhs2 := new(edwards25519.Point).Add(p.V, be)
	if hz.Equal(rhs2) != 1 {
		return false
	}

	return true
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./proof/ -v
```

Expected: PASS (8 tests total).

- [ ] **Step 5: Commit**

```bash
git add crypto/proof/
git commit -m "feat(crypto): add Chaum-Pedersen equality proof"
```

---

## Task 7: SHA-256 Merkle Tree

**Files:**
- Create: `crypto/merkle/merkle.go`
- Create: `crypto/merkle/merkle_test.go`

- [ ] **Step 1: Write Merkle tree tests**

Create `crypto/merkle/merkle_test.go`:

```go
package merkle

import (
	"bytes"
	"testing"
)

func TestEmptyTree(t *testing.T) {
	tree := New()
	if tree.Root() != nil {
		t.Fatal("empty tree should have nil root")
	}
	if tree.Size() != 0 {
		t.Fatal("empty tree should have size 0")
	}
}

func TestAppendAndRoot(t *testing.T) {
	tree := New()
	tree.Append([]byte("ballot1"))
	root1 := tree.Root()
	if root1 == nil {
		t.Fatal("root should not be nil after append")
	}
	tree.Append([]byte("ballot2"))
	root2 := tree.Root()
	if bytes.Equal(root1, root2) {
		t.Fatal("root should change after append")
	}
}

func TestInclusionProof(t *testing.T) {
	tree := New()
	for i := 0; i < 10; i++ {
		tree.Append([]byte{byte(i)})
	}
	for i := 0; i < 10; i++ {
		proof, err := tree.InclusionProof(i)
		if err != nil {
			t.Fatalf("failed to get proof for index %d: %v", i, err)
		}
		if !VerifyInclusion(tree.Root(), []byte{byte(i)}, i, tree.Size(), proof) {
			t.Fatalf("inclusion proof for index %d should verify", i)
		}
	}
}

func TestInclusionProofTampered(t *testing.T) {
	tree := New()
	tree.Append([]byte("real"))
	proof, _ := tree.InclusionProof(0)
	// Verify with wrong data
	if VerifyInclusion(tree.Root(), []byte("fake"), 0, tree.Size(), proof) {
		t.Fatal("tampered data should not verify")
	}
}

func TestAppendOnly(t *testing.T) {
	tree := New()
	tree.Append([]byte("a"))
	root1 := make([]byte, len(tree.Root()))
	copy(root1, tree.Root())
	tree.Append([]byte("b"))

	// Old proof should still verify against the OLD root
	proof, _ := tree.InclusionProof(0)
	if !VerifyInclusion(tree.Root(), []byte("a"), 0, tree.Size(), proof) {
		t.Fatal("old entry should still have valid proof in grown tree")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement Merkle tree**

Create `crypto/merkle/merkle.go`:

```go
package merkle

import (
	"crypto/sha256"
	"errors"
)

// Tree is an append-only SHA-256 Merkle tree.
type Tree struct {
	leaves [][]byte // raw leaf data
	nodes  [][]byte // internal node hashes (level-order)
}

// New creates an empty Merkle tree.
func New() *Tree {
	return &Tree{}
}

// Append adds a leaf to the tree.
func (t *Tree) Append(data []byte) {
	t.leaves = append(t.leaves, data)
	t.rebuild()
}

// Root returns the current Merkle root, or nil if empty.
func (t *Tree) Root() []byte {
	if len(t.nodes) == 0 {
		return nil
	}
	return t.nodes[0]
}

// Size returns the number of leaves.
func (t *Tree) Size() int {
	return len(t.leaves)
}

// Leaf returns the data at the given index.
func (t *Tree) Leaf(index int) ([]byte, error) {
	if index < 0 || index >= len(t.leaves) {
		return nil, errors.New("index out of range")
	}
	return t.leaves[index], nil
}

// InclusionProof returns the sibling hashes needed to verify a leaf.
type ProofNode struct {
	Hash  []byte
	IsLeft bool // true if this sibling is on the left
}

func (t *Tree) InclusionProof(index int) ([]ProofNode, error) {
	if index < 0 || index >= len(t.leaves) {
		return nil, errors.New("index out of range")
	}

	n := len(t.leaves)
	if n == 1 {
		return nil, nil // Single leaf, no proof needed
	}

	// Build leaf hashes
	hashes := make([][]byte, n)
	for i, leaf := range t.leaves {
		hashes[i] = hashLeaf(leaf)
	}

	var proof []ProofNode
	idx := index
	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		sibling := idx ^ 1
		if sibling < len(hashes) {
			proof = append(proof, ProofNode{
				Hash:  hashes[sibling],
				IsLeft: sibling < idx,
			})
		}
		next := make([][]byte, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			next[i/2] = hashPair(hashes[i], hashes[i+1])
		}
		hashes = next
		idx /= 2
	}
	return proof, nil
}

// VerifyInclusion verifies a Merkle inclusion proof.
func VerifyInclusion(root, data []byte, index, size int, proof []ProofNode) bool {
	h := hashLeaf(data)
	for _, p := range proof {
		if p.IsLeft {
			h = hashPair(p.Hash, h)
		} else {
			h = hashPair(h, p.Hash)
		}
	}
	return bytesEqual(h, root)
}

func (t *Tree) rebuild() {
	n := len(t.leaves)
	if n == 0 {
		t.nodes = nil
		return
	}
	hashes := make([][]byte, n)
	for i, leaf := range t.leaves {
		hashes[i] = hashLeaf(leaf)
	}
	if n == 1 {
		t.nodes = hashes
		return
	}
	var allNodes [][]byte
	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		next := make([][]byte, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			next[i/2] = hashPair(hashes[i], hashes[i+1])
		}
		allNodes = append(allNodes, next...)
		hashes = next
	}
	t.nodes = append(hashes, allNodes...)
}

func hashLeaf(data []byte) []byte {
	h := sha256.Sum256(append([]byte{0x00}, data...))
	return h[:]
}

func hashPair(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./merkle/ -v
```

Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add crypto/merkle/
git commit -m "feat(crypto): add SHA-256 append-only Merkle tree"
```

---

## Task 8: Threshold Key Management — Feldman VSS

**Files:**
- Create: `crypto/threshold/feldman.go`
- Create: `crypto/threshold/feldman_test.go`

- [ ] **Step 1: Write Feldman VSS tests**

Create `crypto/threshold/feldman_test.go`:

```go
package threshold

import (
	"testing"

	"filippo.io/edwards25519"
)

func TestFeldmanShareGeneration(t *testing.T) {
	dealer := NewDealer(5, 9) // 5-of-9
	if len(dealer.Commitments) != 5 {
		t.Fatalf("expected 5 commitments, got %d", len(dealer.Commitments))
	}
	if len(dealer.Shares) != 9 {
		t.Fatalf("expected 9 shares, got %d", len(dealer.Shares))
	}
}

func TestFeldmanShareVerification(t *testing.T) {
	dealer := NewDealer(5, 9)
	for i := 0; i < 9; i++ {
		if !VerifyShare(dealer.Shares[i], i+1, dealer.Commitments) {
			t.Fatalf("share %d should verify", i+1)
		}
	}
}

func TestFeldmanShareVerificationTampered(t *testing.T) {
	dealer := NewDealer(5, 9)
	// Tamper with a share
	dealer.Shares[0] = new(edwards25519.Scalar).Add(dealer.Shares[0], dealer.Shares[1])
	if VerifyShare(dealer.Shares[0], 1, dealer.Commitments) {
		t.Fatal("tampered share should NOT verify")
	}
}

func TestFeldmanReconstruction(t *testing.T) {
	dealer := NewDealer(5, 9)
	// Use first 5 shares to reconstruct the secret
	indices := []int{1, 2, 3, 4, 5}
	shares := make([]*edwards25519.Scalar, 5)
	for i, idx := range indices {
		shares[i] = dealer.Shares[idx-1]
	}
	secret := LagrangeInterpolate(shares, indices)

	// The secret should equal the dealer's a_0 coefficient
	expected := dealer.Secret()
	if secret.Equal(expected) != 1 {
		t.Fatal("reconstructed secret should match dealer's secret")
	}
}

func TestFeldmanReconstructionSubset(t *testing.T) {
	dealer := NewDealer(5, 9)
	// Use shares 3, 5, 7, 8, 9
	indices := []int{3, 5, 7, 8, 9}
	shares := make([]*edwards25519.Scalar, 5)
	for i, idx := range indices {
		shares[i] = dealer.Shares[idx-1]
	}
	secret := LagrangeInterpolate(shares, indices)
	if secret.Equal(dealer.Secret()) != 1 {
		t.Fatal("any 5-of-9 subset should reconstruct the same secret")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement Feldman VSS**

Create `crypto/threshold/feldman.go`:

```go
package threshold

import (
	"math/big"

	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/internal"
)

// Dealer holds the state for Feldman's Verifiable Secret Sharing.
type Dealer struct {
	coefficients []*edwards25519.Scalar // polynomial coefficients a_0, ..., a_{t-1}
	Commitments  []*edwards25519.Point  // g^{a_k} for each coefficient
	Shares       []*edwards25519.Scalar // f(i) for i = 1..n
}

// NewDealer generates a random polynomial of degree t-1 and computes shares for n parties.
func NewDealer(threshold, numParties int) *Dealer {
	coeffs := make([]*edwards25519.Scalar, threshold)
	commitments := make([]*edwards25519.Point, threshold)

	for k := 0; k < threshold; k++ {
		coeffs[k] = internal.RandomScalar()
		commitments[k] = new(edwards25519.Point).ScalarBaseMult(coeffs[k])
	}

	shares := make([]*edwards25519.Scalar, numParties)
	for i := 1; i <= numParties; i++ {
		shares[i-1] = evaluatePolynomial(coeffs, i)
	}

	return &Dealer{
		coefficients: coeffs,
		Commitments:  commitments,
		Shares:       shares,
	}
}

// Secret returns the secret value a_0 (the constant term).
func (d *Dealer) Secret() *edwards25519.Scalar {
	return d.coefficients[0]
}

// PublicKey returns g^{a_0}, the public key corresponding to the secret.
func (d *Dealer) PublicKey() *edwards25519.Point {
	return d.Commitments[0]
}

// VerifyShare verifies that share s_i is consistent with the published commitments.
// index is 1-based (trustee number).
func VerifyShare(share *edwards25519.Scalar, index int, commitments []*edwards25519.Point) bool {
	// g^{f(i)} should equal product of C_k^{i^k}
	lhs := new(edwards25519.Point).ScalarBaseMult(share)

	rhs := edwards25519.NewIdentityPoint()
	iPow := big.NewInt(1)
	iBig := big.NewInt(int64(index))

	for k, ck := range commitments {
		if k > 0 {
			iPow.Mul(iPow, iBig)
		}
		exp := scalarFromBigInt(iPow)
		term := new(edwards25519.Point).ScalarMult(exp, ck)
		rhs.Add(rhs, term)
	}

	return lhs.Equal(rhs) == 1
}

// LagrangeInterpolate reconstructs the secret from t shares using Lagrange interpolation.
// indices are 1-based.
func LagrangeInterpolate(shares []*edwards25519.Scalar, indices []int) *edwards25519.Scalar {
	secret := edwards25519.NewScalar()
	for i, si := range shares {
		lambda := lagrangeCoefficient(indices, i)
		term := new(edwards25519.Scalar).Multiply(lambda, si)
		secret.Add(secret, term)
	}
	return secret
}

// LagrangeCoefficientPoint computes the Lagrange coefficient for use in
// combining partial decryptions (point exponentiation).
func LagrangeCoefficientPoint(indices []int, myIndex int) *edwards25519.Scalar {
	return lagrangeCoefficient(indices, myIndex)
}

func lagrangeCoefficient(indices []int, myIdx int) *edwards25519.Scalar {
	// lambda_i = product_{j != i} (x_j / (x_j - x_i)) where x_j = indices[j]
	q := edwards25519Order()
	num := big.NewInt(1)
	den := big.NewInt(1)
	xi := big.NewInt(int64(indices[myIdx]))

	for j, xj := range indices {
		if j == myIdx {
			continue
		}
		xjBig := big.NewInt(int64(xj))
		num.Mul(num, xjBig)
		num.Mod(num, q)
		diff := new(big.Int).Sub(xjBig, xi)
		diff.Mod(diff, q)
		den.Mul(den, diff)
		den.Mod(den, q)
	}

	denInv := new(big.Int).ModInverse(den, q)
	result := new(big.Int).Mul(num, denInv)
	result.Mod(result, q)

	return scalarFromBigInt(result)
}

func evaluatePolynomial(coeffs []*edwards25519.Scalar, x int) *edwards25519.Scalar {
	// Horner's method: f(x) = a_0 + x*(a_1 + x*(a_2 + ...))
	xScalar := scalarFromBigInt(big.NewInt(int64(x)))
	result := edwards25519.NewScalar()
	for k := len(coeffs) - 1; k >= 0; k-- {
		result.Multiply(result, xScalar)
		result.Add(result, coeffs[k])
	}
	return result
}

func edwards25519Order() *big.Int {
	q, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	return q
}

func scalarFromBigInt(n *big.Int) *edwards25519.Scalar {
	q := edwards25519Order()
	n = new(big.Int).Mod(n, q)
	var buf [32]byte
	b := n.Bytes()
	for i, v := range b {
		buf[len(b)-1-i] = v // little-endian
	}
	s, err := edwards25519.NewScalar().SetCanonicalBytes(buf[:])
	if err != nil {
		panic("scalarFromBigInt: " + err.Error())
	}
	return s
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./threshold/ -v
```

Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add crypto/threshold/
git commit -m "feat(crypto): add Feldman VSS and Lagrange interpolation"
```

---

## Task 9: Threshold Decryption and DKG

**Files:**
- Create: `crypto/threshold/decrypt.go`
- Create: `crypto/threshold/decrypt_test.go`
- Create: `crypto/threshold/dkg.go`
- Create: `crypto/threshold/dkg_test.go`

- [ ] **Step 1: Write threshold decryption tests**

Create `crypto/threshold/decrypt_test.go`:

```go
package threshold

import (
	"testing"

	"github.com/valy0/otvoren-vot/crypto/elgamal"
)

func TestPartialDecryptAndCombine(t *testing.T) {
	dealer := NewDealer(5, 9)
	pk := dealer.PublicKey()

	ct := elgamal.Encrypt(pk, 42)

	// Each of 5 trustees computes a partial decryption
	indices := []int{1, 3, 5, 7, 9}
	partials := make([]*PartialDecryption, 5)
	for i, idx := range indices {
		partials[i] = PartialDecrypt(dealer.Shares[idx-1], ct)
	}

	// Combine and recover plaintext
	m := CombinePartials(ct, partials, indices, 5_000_000)
	if m != 42 {
		t.Fatalf("expected 42, got %d", m)
	}
}

func TestPartialDecryptionProof(t *testing.T) {
	dealer := NewDealer(5, 9)
	pk := dealer.PublicKey()
	ct := elgamal.Encrypt(pk, 1)

	share := dealer.Shares[0]
	verificationKey := new(edwards25519.Point).ScalarBaseMult(share)

	pd := PartialDecryptWithProof(share, ct, verificationKey)
	if !VerifyPartialDecryption(ct, pd, verificationKey) {
		t.Fatal("valid partial decryption proof should verify")
	}
}
```

Note: need to add import for edwards25519 in the test file.

- [ ] **Step 2: Write DKG tests**

Create `crypto/threshold/dkg_test.go`:

```go
package threshold

import (
	"testing"

	"github.com/valy0/otvoren-vot/crypto/elgamal"
)

func TestDKGFullProtocol(t *testing.T) {
	numTrustees := 9
	threshold := 5

	// Step 1: Each trustee acts as a dealer
	dealers := make([]*Dealer, numTrustees)
	for i := 0; i < numTrustees; i++ {
		dealers[i] = NewDealer(threshold, numTrustees)
	}

	// Step 2: Each trustee combines received shares
	combinedShares := make([]*edwards25519.Scalar, numTrustees)
	for i := 0; i < numTrustees; i++ {
		combinedShares[i] = edwards25519.NewScalar()
		for j := 0; j < numTrustees; j++ {
			combinedShares[i].Add(combinedShares[i], dealers[j].Shares[i])
		}
	}

	// Step 3: Compute combined public key
	combinedPK := edwards25519.NewIdentityPoint()
	for _, d := range dealers {
		combinedPK.Add(combinedPK, d.PublicKey())
	}

	// Step 4: Encrypt and threshold-decrypt
	ct := elgamal.Encrypt(combinedPK, 7)

	indices := []int{1, 2, 3, 4, 5}
	partials := make([]*PartialDecryption, threshold)
	for i, idx := range indices {
		partials[i] = PartialDecrypt(combinedShares[idx-1], ct)
	}

	m := CombinePartials(ct, partials, indices, 100)
	if m != 7 {
		t.Fatalf("DKG: expected 7, got %d", m)
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

- [ ] **Step 4: Implement partial decryption**

Create `crypto/threshold/decrypt.go`:

```go
package threshold

import (
	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/proof"
)

// PartialDecryption holds a trustee's decryption share and optional proof.
type PartialDecryption struct {
	D     *edwards25519.Point      // c1^{x_i}
	Proof *proof.ChaumPedersenProof // optional proof of correct computation
}

// PartialDecrypt computes a partial decryption of ct using the trustee's share.
// d_i = c1^{x_i}
func PartialDecrypt(share *edwards25519.Scalar, ct *elgamal.Ciphertext) *PartialDecryption {
	d := new(edwards25519.Point).ScalarMult(share, ct.C1)
	return &PartialDecryption{D: d}
}

// PartialDecryptWithProof computes a partial decryption with a Chaum-Pedersen proof
// that d_i = c1^{x_i} is consistent with the verification key h_i = g^{x_i}.
func PartialDecryptWithProof(share *edwards25519.Scalar, ct *elgamal.Ciphertext, verificationKey *edwards25519.Point) *PartialDecryption {
	d := new(edwards25519.Point).ScalarMult(share, ct.C1)
	g := edwards25519.NewGeneratorPoint()
	p := proof.ProveChaumPedersen(g, ct.C1, verificationKey, d, share)
	return &PartialDecryption{D: d, Proof: p}
}

// VerifyPartialDecryption checks the Chaum-Pedersen proof on a partial decryption.
func VerifyPartialDecryption(ct *elgamal.Ciphertext, pd *PartialDecryption, verificationKey *edwards25519.Point) bool {
	if pd.Proof == nil {
		return false
	}
	g := edwards25519.NewGeneratorPoint()
	return proof.VerifyChaumPedersen(g, ct.C1, verificationKey, pd.D, pd.Proof)
}

// CombinePartials combines threshold partial decryptions and recovers the plaintext.
// indices are 1-based trustee IDs.
func CombinePartials(ct *elgamal.Ciphertext, partials []*PartialDecryption, indices []int, maxPlaintext int) int {
	// D = product of d_i^{lambda_i}
	combined := edwards25519.NewIdentityPoint()
	for i := range partials {
		lambda := LagrangeCoefficientPoint(indices, i)
		term := new(edwards25519.Point).ScalarMult(lambda, partials[i].D)
		combined.Add(combined, term)
	}

	// g^m = c2 - D
	negD := new(edwards25519.Point).Negate(combined)
	gm := new(edwards25519.Point).Add(ct.C2, negD)

	// Solve discrete log via BSGS
	return solveDL(gm, maxPlaintext)
}

// solveDL finds m such that g^m = target, for m in [0, max].
func solveDL(target *edwards25519.Point, max int) int {
	step := 1
	for step*step < max {
		step++
	}

	g := edwards25519.NewGeneratorPoint()

	table := make(map[[32]byte]int, step)
	current := edwards25519.NewIdentityPoint()
	for j := 0; j < step; j++ {
		var key [32]byte
		copy(key[:], current.Bytes())
		table[key] = j
		current.Add(current, g)
	}

	stepScalar := scalarFromBigInt(big.NewInt(int64(step)))
	giantStep := new(edwards25519.Point).ScalarBaseMult(stepScalar)
	giantStep.Negate(giantStep)

	gamma := new(edwards25519.Point).Set(target)
	for i := 0; i <= max/step+1; i++ {
		var key [32]byte
		copy(key[:], gamma.Bytes())
		if j, ok := table[key]; ok {
			return i*step + j
		}
		gamma.Add(gamma, giantStep)
	}
	return -1
}
```

Note: add `"math/big"` to imports.

- [ ] **Step 5: Run tests**

```bash
go test ./threshold/ -v
```

Expected: PASS (7 tests — 5 Feldman + 2 decrypt).

- [ ] **Step 6: Run all crypto tests**

```bash
go test ./... -v
```

Expected: ALL PASS.

- [ ] **Step 7: Commit**

```bash
git add crypto/threshold/
git commit -m "feat(crypto): add threshold decryption, DKG, and partial decryption proofs"
```

---

## Task 10: Integration Test — Full Election Simulation

**Files:**
- Create: `crypto/integration_test.go`

- [ ] **Step 1: Write end-to-end election simulation test**

Create `crypto/integration_test.go`:

```go
package crypto_test

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/elgamal"
	"github.com/valy0/otvoren-vot/crypto/merkle"
	"github.com/valy0/otvoren-vot/crypto/proof"
	"github.com/valy0/otvoren-vot/crypto/internal"
	"github.com/valy0/otvoren-vot/crypto/threshold"
)

func TestFullElectionSimulation(t *testing.T) {
	const (
		numTrustees = 9
		thresh      = 5
		numParties  = 5
		numVoters   = 20
	)

	// === DKG ===
	dealers := make([]*threshold.Dealer, numTrustees)
	for i := range dealers {
		dealers[i] = threshold.NewDealer(thresh, numTrustees)
	}

	combinedShares := make([]*edwards25519.Scalar, numTrustees)
	for i := 0; i < numTrustees; i++ {
		combinedShares[i] = edwards25519.NewScalar()
		for j := 0; j < numTrustees; j++ {
			combinedShares[i].Add(combinedShares[i], dealers[j].Shares[i])
		}
	}

	electionPK := edwards25519.NewIdentityPoint()
	for _, d := range dealers {
		electionPK.Add(electionPK, d.PublicKey())
	}

	// === VOTING ===
	tree := merkle.New()
	ballots := make([]*elgamal.Ballot, numVoters)
	expectedTally := make([]int, numParties)

	// Votes: distribute across parties
	for i := 0; i < numVoters; i++ {
		party := i % numParties
		expectedTally[party]++
		ballots[i] = elgamal.EncodeBallot(electionPK, numParties, party, -1)

		// Append serialized ballot to Merkle tree
		data := []byte{byte(i)} // simplified ballot ID
		tree.Append(data)
	}

	// Verify Merkle inclusion for each ballot
	for i := 0; i < numVoters; i++ {
		p, err := tree.InclusionProof(i)
		if err != nil {
			t.Fatalf("voter %d: inclusion proof failed: %v", i, err)
		}
		if !merkle.VerifyInclusion(tree.Root(), []byte{byte(i)}, i, tree.Size(), p) {
			t.Fatalf("voter %d: inclusion verification failed", i)
		}
	}

	// === TALLY ===
	tally := elgamal.TallyBallots(ballots)

	// === THRESHOLD DECRYPTION ===
	indices := []int{1, 3, 5, 7, 9}
	for partyIdx := 0; partyIdx < numParties; partyIdx++ {
		partials := make([]*threshold.PartialDecryption, thresh)
		for i, idx := range indices {
			partials[i] = threshold.PartialDecrypt(combinedShares[idx-1], tally.PartyVector[partyIdx])
		}
		result := threshold.CombinePartials(tally.PartyVector[partyIdx], partials, indices, 100)
		if result != expectedTally[partyIdx] {
			t.Fatalf("party %d: expected %d votes, got %d", partyIdx, expectedTally[partyIdx], result)
		}
	}

	t.Logf("Election simulation passed: %d voters, %d parties, tally correct", numVoters, numParties)
}
```

- [ ] **Step 2: Run integration test**

```bash
go test -v -run TestFullElectionSimulation
```

Expected: PASS.

- [ ] **Step 3: Run all tests with race detector**

```bash
go test ./... -race -v
```

Expected: ALL PASS, no races.

- [ ] **Step 4: Commit**

```bash
git add crypto/integration_test.go
git commit -m "test(crypto): add full election simulation integration test"
```

---

## Execution Notes

- **Tasks 1-2** must be sequential (module init → ElGamal depends on scalars).
- **Task 3** depends on Task 2 (ballot uses ElGamal).
- **Tasks 4-6** depend on Tasks 1-2 (proofs use ElGamal + scalars) but are independent of each other.
- **Task 7** (Merkle) is independent of Tasks 2-6 — can run in parallel.
- **Task 8** depends on Task 1 (scalars) but is independent of Tasks 2-7.
- **Task 9** depends on Tasks 6 and 8 (decryption uses Chaum-Pedersen + Feldman).
- **Task 10** depends on all previous tasks.
- The code in this plan may need minor adjustments during implementation (import paths, method signatures). The implementer should use the protocol docs as the authoritative reference.
