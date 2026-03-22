# Cryptographic Protocol Overview

**System:** otvoren-vot — end-to-end verifiable e-voting for Bulgarian national elections
**Status:** Specification draft
**Audience:** Developers, auditors, cryptographers reviewing the system design

---

## 1. Protocol Summary

Otvoren-vot cryptographically proves the following properties to the public, without revealing any individual vote:

| Property | What is proven | To whom |
|----------|---------------|---------|
| **Ballot validity** | Every accepted ballot encodes exactly one party choice and at most one candidate preference, using only 0/1 values | Anyone verifying the bulletin board |
| **Inclusion** | A specific ballot (identified by random ID) is present in the Merkle tree at a known position | The voter who cast it |
| **Honest deduplication** | The set of ballots entering the tally matches the committed active set exactly — no ballots added, removed, or substituted | Anyone verifying the SNARK proof |
| **Honest partial decryption** | Each trustee's decryption share was computed correctly from the encrypted tally sums using their secret key share | Anyone verifying the Chaum-Pedersen proofs |
| **Tally correctness** | The published plaintext results are the correct decryption of the homomorphic sums | Anyone who re-checks the decryption math and proofs |
| **Append-only board** | The bulletin board was never retroactively modified during the election | External monitors who store the signed root sequence |

No individual ballot is ever decrypted. The tally is computed homomorphically over ciphertexts, and only the aggregate sums are decrypted by threshold trustees during a public ceremony.

---

## 2. Cryptographic Groups

The system uses **two distinct algebraic groups** for different purposes. They never interact inside a circuit.

### 2.1 Ristretto255 — ElGamal encryption and Sigma proofs

**What it is:** A prime-order group of order `q` constructed from Curve25519. Ristretto255 applies a quotient-group construction that eliminates the cofactor issues present in raw Ed25519, producing a clean prime-order group where every encoded point is valid and encoding is canonical.

**Group order:**
```
q = 2^252 + 27742317777372353535851937790883648493
  = 7237005577332262213973186563042994240857116359379907606001950938285454250989
```

This is approximately `2^252`, providing ~126 bits of security against discrete-log attacks (generic Pollard's rho).

**Why Ristretto255:**
- Prime-order group eliminates small-subgroup attacks — no cofactor checks needed
- Canonical encoding — every point has exactly one valid byte representation, preventing subtle malleability bugs
- Built on Curve25519, one of the most studied and optimized elliptic curves
- Fast: constant-time scalar multiplication in ~120 microseconds on modern hardware
- Excellent library support: `filippo.io/edwards25519` (Go), `libsodium` (C/WASM) both provide native Ristretto255 APIs

**Used for:** ElGamal ballot encryption, homomorphic tallying, Chaum-Pedersen proofs, Sigma proofs of ballot validity.

### 2.2 BN254 — gnark SNARK circuits

**What it is:** A pairing-friendly elliptic curve (also called BN128 or alt_bn128) with a ~254-bit prime field. It supports efficient bilinear pairings, which are required by the Groth16 proof system.

**Security level:** ~100-110 bits (recent NFS improvements have reduced the estimated security of BN254 below 128 bits, but it remains sufficient for election-duration security and is the most mature curve supported by gnark).

**Why BN254:**
- gnark's most optimized and battle-tested backend
- The Poseidon hash function is defined natively over the BN254 scalar field, making it extremely cheap inside circuits (~250 R1CS constraints per hash invocation)
- Well-understood trusted setup procedures (Groth16)
- Proven in production by Ethereum's precompiled contracts and many ZK-rollup systems

**Used for:** The ZK deduplication circuit (proving that the filtered ballot set matches the committed active set), computed inside a Groth16 SNARK.

### 2.3 Why two groups — and why they do not interact

ElGamal encryption requires a group where the discrete logarithm problem is hard and where we can do efficient multi-scalar multiplication (for homomorphic tallying of millions of ballots). Ristretto255 is ideal for this — it is fast, safe, and well-supported.

SNARK circuits require a pairing-friendly curve. Ristretto255 does not support pairings, so it cannot be used for Groth16. BN254 supports pairings but is slower for bulk scalar multiplication and has lower security margin.

**The groups never interact inside a circuit.** The SNARK circuit operates entirely in BN254-native field arithmetic — it verifies Poseidon Merkle proofs, set membership, and count checks. The ElGamal homomorphic product (multiplying ciphertexts over Ristretto255) and threshold decryption happen *outside* the SNARK, verified by separate Sigma and Chaum-Pedersen proofs over the Ristretto255 group. If we tried to verify Ristretto255 operations inside a BN254 circuit, the field-mismatch would require non-native arithmetic emulation, inflating the circuit by orders of magnitude.

---

## 3. Proof Framework

The system uses two proof frameworks, chosen based on proof complexity:

### 3.1 Sigma Protocols (Chaum-Pedersen family)

**What they are:** Three-move interactive proofs (commit, challenge, response) made non-interactive via the Fiat-Shamir heuristic (challenge = hash of transcript). They are simple, fast, and produce short proofs.

**When to use:** Proofs about discrete-log relationships over Ristretto255 — "I know the exponent," "these two values share the same exponent," "this ciphertext encrypts 0 or 1."

**Properties:**
- Proof size: 64-128 bytes per statement
- Verification: 2-4 scalar multiplications per proof
- Prover time: microseconds to low milliseconds
- No trusted setup
- Honest-verifier zero-knowledge (HVZK), which becomes full ZK under Fiat-Shamir in the random oracle model

**Used for:**
- Ballot validity proofs (each element is 0 or 1; vectors sum correctly)
- Partial decryption proofs (Chaum-Pedersen: trustee's share is correctly computed)
- Tally correctness proof (the final plaintext matches the decrypted ciphertext)

### 3.2 gnark Groth16 SNARKs

**What they are:** Succinct Non-interactive Arguments of Knowledge. The prover produces a constant-size proof (~192 bytes for BN254 Groth16) that a private witness satisfies a public circuit. Verification is fast (~3 pairings) regardless of circuit size.

**When to use:** Complex statements that cannot be expressed as simple discrete-log relations — set membership over Merkle trees, equality of commitments, counting constraints. Essentially, when the statement involves thousands of operations that must be verified together.

**Properties:**
- Proof size: ~192 bytes (constant, regardless of circuit size)
- Verification: ~1.5 ms (3 pairing checks)
- Prover time: minutes to hours depending on circuit size (parallelizable)
- **Requires trusted setup** — a circuit-specific Common Reference String (CRS) generated via a multi-party computation ceremony. At least one honest participant is sufficient for soundness.
- Knowledge soundness under the Knowledge of Exponent assumption on BN254

**Used for:**
- Deduplication proof: the filtered ballot set matches the committed active set, every included ballot has a valid Merkle path, the count is correct

### 3.3 Decision criteria

| Criterion | Sigma protocol | Groth16 SNARK |
|-----------|---------------|---------------|
| Statement type | DLog relations over a single group | Arbitrary arithmetic circuits |
| Proof size | O(statements) | O(1) — constant |
| Prover cost | Microseconds | Minutes to hours |
| Verifier cost | O(statements) | O(1) — constant |
| Trusted setup | No | Yes (per circuit) |
| Group | Ristretto255 | BN254 |

**Rule of thumb:** If the proof is about ElGamal ciphertexts and can be expressed as a handful of discrete-log equalities or OR-proofs, use a Sigma protocol. If the proof involves Merkle tree traversals, set operations, or thousands of interrelated constraints, use a Groth16 SNARK.

---

## 4. Dual-Hash Merkle Tree

The bulletin board maintains **two parallel Merkle trees**, both computed on every ballot append. They cover the same data but use different hash functions.

### 4.1 SHA-256 public tree

- **Purpose:** External verification, API responses, inclusion proofs returned to voters
- **Hash function:** SHA-256 (NIST standard, universally implemented)
- **Who verifies:** Voters (via `verify.izbori.bg`), political parties, NGOs, media, independent auditors
- **Properties:** Anyone with `sha256sum` can rebuild the tree from raw data and confirm the root

### 4.2 Poseidon SNARK tree

- **Purpose:** Used exclusively inside the gnark deduplication circuit
- **Hash function:** Poseidon over the BN254 scalar field
- **Who verifies:** The Groth16 verifier (a smart computation, not a human)
- **Properties:** Algebraically native to BN254 — each hash invocation costs ~250 R1CS constraints

### 4.3 Why two trees

The deduplication circuit must verify Merkle inclusion proofs *inside* the SNARK. If we used SHA-256, each hash would cost ~25,000 R1CS constraints (SHA-256 is a bitwise function that must be emulated in an arithmetic circuit field). For a tree of depth 20 with thousands of inclusion proofs, this would make the circuit infeasibly large.

Poseidon is an algebraic hash function designed for arithmetic circuits. It operates directly on field elements using only additions and exponentiations — precisely the operations that are cheap in R1CS. At ~250 constraints per hash, a depth-20 Merkle path requires ~5,000 constraints instead of ~500,000.

| Hash | Constraints per invocation | Depth-20 path cost | Notes |
|------|---------------------------|-------------------|-------|
| SHA-256 | ~25,000 | ~500,000 | Standard, universally verifiable |
| Poseidon/BN254 | ~250 | ~5,000 | SNARK-native, ~100x cheaper in-circuit |

The public SHA-256 tree is canonical. The Poseidon tree is an internal optimization that exists solely to make the deduplication SNARK computationally tractable. Both trees cover identical data and are computed on every append, so their roots are always consistent.

---

## 5. Four Proofs

| # | Proof | What it proves | Framework | When published |
|---|-------|---------------|-----------|----------------|
| 1 | **Ballot validity** | Each encrypted element is `Enc(0)` or `Enc(1)`. The party vector sums to exactly 1. Each candidate vector sums to 0 or 1, and only the selected party's candidate vector may be nonzero. | Sigma (OR-proof + sum-proof) | At ballot submission — attached to each ballot on the bulletin board |
| 2 | **Deduplication** | The filtered set of ballots entering the tally matches the committed active set: every included ballot has a valid Merkle path, the set of IDs equals the committed set, and the count matches. | gnark Groth16 SNARK (with recursive composition for batching) | During the decryption ceremony, before tallying begins |
| 3 | **Partial decryption** | Each trustee's partial decryption share `d_i = c1^{x_i}` was computed using the correct secret key share `x_i` corresponding to their published verification key `h_i = g^{x_i}`. | Chaum-Pedersen (Sigma) | During the decryption ceremony, as each trustee contributes |
| 4 | **Tally correctness** | The published plaintext vote totals are the correct decryption of the homomorphic ciphertext sums. Combines verification of all partial decryptions and the final discrete-log recovery. | Sigma + BSGS verification | End of decryption ceremony |

### Proof lifecycle

```
Election day:
  Each ballot submitted → ballot validity proof attached (Sigma, instant)

Polls close (20:00):
  Bulletin board sealed
  Active set commitment published by Layer 1

Ceremony (~20:05 - ~21:15):
  1. Deduplication SNARK generated (~30-60 min, parallelized)
     → Published on bulletin board
  2. Homomorphic tally computed (element-wise ciphertext multiplication)
  3. Trustees contribute partial decryptions, each with Chaum-Pedersen proof
     → Published as each trustee finishes
  4. Partial decryptions combined, discrete logs recovered via BSGS
  5. Tally correctness proof published
  6. Plaintext results displayed
```

---

## 6. Security Assumptions

The system's end-to-end verifiability and ballot secrecy rest on the following computational assumptions:

### 6.1 Discrete Logarithm Hardness on Ristretto255

**Assumption:** Given `g` and `h = g^x` in the Ristretto255 group, no polynomial-time adversary can compute `x` with non-negligible probability.

**Security level:** ~126 bits (group order ~2^252; best known attack is Pollard's rho at O(sqrt(q)) = O(2^126) group operations).

**What depends on it:**
- Ballot secrecy — ElGamal ciphertext `(g^r, h^r * g^m)` is semantically secure under the Decisional Diffie-Hellman (DDH) assumption, which follows from DLog hardness in prime-order groups
- Sigma proof soundness — a cheating prover who can break a Sigma proof can solve the discrete log problem
- Homomorphic tally privacy — the encrypted sums reveal only the aggregate, not individual votes

### 6.2 Knowledge of Exponent on BN254

**Assumption:** The Knowledge of Exponent (KEA) assumption on the BN254 pairing group states that any adversary who produces a valid group element pair `(A, B)` such that `e(A, g2) = e(g1, B)` (where `e` is the bilinear pairing) must "know" the discrete logarithm relating them.

**What depends on it:**
- Groth16 knowledge soundness — the deduplication SNARK is a proof of *knowledge*, not just a proof of existence. An adversary cannot produce a valid proof without knowing a valid witness (the actual active set and Merkle paths).

### 6.3 Groth16 Soundness and Trusted Setup

**Assumption:** The Groth16 proof system is sound (no false proofs can be constructed) provided the Common Reference String (CRS) was honestly generated — specifically, that the "toxic waste" (the secret randomness used during setup) was destroyed.

**Trusted setup requirement:** A multi-party computation (MPC) ceremony generates the CRS. The ceremony is secure as long as **at least one participant** behaves honestly and destroys their secret contribution. This is a standard ceremony format used by Zcash, Ethereum, and other production systems.

**What depends on it:**
- Deduplication proof soundness — if the CRS is compromised (all participants colluded), a malicious Tally Service could forge a deduplication proof for a fraudulent ballot set. However, this would still be detectable via the voter count cross-check (active set size must match the number of voters observed by party observers at polling stations).

### 6.4 Random Oracle Model

**Assumption:** The Fiat-Shamir heuristic (used to make Sigma protocols non-interactive) models the hash function as a random oracle. In practice, SHA-256 or BLAKE2b is used.

**What depends on it:**
- Non-interactive Sigma proof soundness — the challenge is derived from the transcript hash rather than from an interactive verifier

### 6.5 Summary of security levels

| Component | Assumption | Estimated security |
|-----------|-----------|-------------------|
| ElGamal / Sigma proofs | DLog on Ristretto255 | ~126 bits |
| Groth16 SNARK | KEA on BN254 | ~100-110 bits |
| Fiat-Shamir | Random oracle (SHA-256) | 128 bits (collision resistance) |
| Threshold scheme | DLog + honest majority (5 of 9 trustees) | Information-theoretic for secrecy; computational for verifiability |

The weakest link is BN254 at ~100-110 bits. This is sufficient for election-duration security (the proofs need to withstand attack only until results are certified and publicly verified, typically days to weeks). Future versions may migrate to BLS12-381 (~120 bits) when gnark support matures, at the cost of larger field elements and slower proving.
