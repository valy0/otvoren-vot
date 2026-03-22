# Zero-Knowledge Ballot Validity Proofs

**System:** otvoren-vot — End-to-end verifiable e-voting for Bulgarian national elections
**Group:** Ristretto255 (prime-order group over Curve25519, order q ≈ 2^252)
**Encryption:** Exponential ElGamal
**Framework:** Sigma protocols (Chaum-Pedersen) with Fiat-Shamir transform

---

## 1. Sigma Protocol Structure

All ballot validity proofs use Sigma protocols — three-move honest-verifier zero-knowledge proofs made non-interactive via the Fiat-Shamir heuristic.

### 1.1 Interactive Protocol (Three Moves)

A Sigma protocol for relation R = {(x; w) : φ(x, w) = true} proceeds as:

```
Prover                              Verifier
------                              --------
knows: (x, w)                       knows: x

1. COMMITMENT
   Choose random nonce k
   Compute commitment A = f(k)
                          ----A---->

2. CHALLENGE
                          <---e----  Choose random e ∈ Z_q

3. RESPONSE
   Compute z = g(k, w, e)
                          ----z---->

                                     VERIFY: V(x, A, e, z) = true
```

Properties:
- **Completeness:** An honest prover always convinces the verifier.
- **Special soundness:** Given two accepting transcripts (A, e, z) and (A, e', z') with e ≠ e', one can extract the witness w.
- **Honest-verifier zero-knowledge:** Given any challenge e, one can simulate a valid transcript (A, e, z) without knowing w.

### 1.2 Fiat-Shamir Transform (Non-Interactive)

Replace the verifier's random challenge with a hash of the commitment and public inputs:

```
e = H(x || A)
```

where H is a cryptographic hash function (SHA-512 mod q, using libsodium's `crypto_hash_sha512` then reducing modulo the Ristretto255 group order).

The non-interactive proof is the tuple π = (A, z). The verifier recomputes e = H(x || A) and checks the verification equation.

**Domain separation:** To prevent cross-protocol attacks, the hash input is prefixed with a domain separator string:

```
e = H("otvoren-vot.ballot-binary-proof" || x || A)
```

Each proof type uses a distinct domain separator.

---

## 2. Proof That an Encrypted Value Is 0 or 1

### 2.1 Setup

Let G be the Ristretto255 base point and H be the election public key (a group element whose discrete log with respect to G is the election secret key, distributed among trustees).

Exponential ElGamal encryption of message m ∈ {0, 1} with randomness r ∈ Z_q:

```
Enc(m; r) = (C₁, C₂) = (r·G, r·H + m·G)
```

Note: We use additive notation for the Ristretto255 group (scalar multiplication written as s·P, group operation as P + Q).

The prover knows (m, r) and wants to prove m ∈ {0, 1} without revealing which.

### 2.2 Disjunctive Chaum-Pedersen Proof (OR-Proof)

This is a proof of the disjunction: "m = 0 OR m = 1". Exactly one branch is proven honestly; the other is simulated. The verifier cannot distinguish which branch was simulated.

**Observation:** If m = 0, then C₂ = r·H (so C₂ is a "Diffie-Hellman pair" with C₁ relative to G and H). If m = 1, then C₂ - G = r·H (so C₂ - G is the Diffie-Hellman pair).

We prove: DLOG_G(C₁) = DLOG_H(C₂) OR DLOG_G(C₁) = DLOG_H(C₂ - G).

#### Case: m = 0 (honest branch 0, simulated branch 1)

The prover knows r such that C₁ = r·G and C₂ = r·H.

```
STEP 1 — Commitment:
  Branch 0 (honest):
    Choose random k₀ ∈ Z_q
    A₀ = k₀·G
    B₀ = k₀·H

  Branch 1 (simulated):
    Choose random e₁, z₁ ∈ Z_q
    A₁ = z₁·G - e₁·C₁
    B₁ = z₁·H - e₁·(C₂ - G)

STEP 2 — Challenge:
    e = H_hash("otvoren-vot.ballot-binary-proof" || C₁ || C₂ || A₀ || B₀ || A₁ || B₁)
    e₀ = e - e₁ (mod q)

STEP 3 — Response:
    z₀ = k₀ + e₀·r (mod q)
```

Proof: π = (A₀, B₀, A₁, B₁, e₀, e₁, z₀, z₁)

#### Case: m = 1 (honest branch 1, simulated branch 0)

The prover knows r such that C₁ = r·G and C₂ - G = r·H.

```
STEP 1 — Commitment:
  Branch 0 (simulated):
    Choose random e₀, z₀ ∈ Z_q
    A₀ = z₀·G - e₀·C₁
    B₀ = z₀·H - e₀·C₂

  Branch 1 (honest):
    Choose random k₁ ∈ Z_q
    A₁ = k₁·G
    B₁ = k₁·H

STEP 2 — Challenge:
    e = H_hash("otvoren-vot.ballot-binary-proof" || C₁ || C₂ || A₀ || B₀ || A₁ || B₁)
    e₁ = e - e₀ (mod q)

STEP 3 — Response:
    z₁ = k₁ + e₁·r (mod q)
```

### 2.3 Verification

Given ciphertext (C₁, C₂) and proof π = (A₀, B₀, A₁, B₁, e₀, e₁, z₀, z₁):

```
1. Recompute challenge:
   e = H_hash("otvoren-vot.ballot-binary-proof" || C₁ || C₂ || A₀ || B₀ || A₁ || B₁)

2. Check challenge partition:
   e₀ + e₁ ≡ e (mod q)

3. Check branch 0 equations:
   z₀·G = A₀ + e₀·C₁
   z₀·H = B₀ + e₀·C₂

4. Check branch 1 equations:
   z₁·G = A₁ + e₁·C₁
   z₁·H = B₁ + e₁·(C₂ - G)
```

All four equations must hold. If any fails, the proof is invalid.

**Why this works:** The simulated branch produces a valid transcript by construction (the simulator chooses e_i, z_i first and computes A_i, B_i to satisfy the verification equations). The honest branch's transcript is valid because the prover knows the witness r. The challenge partition e₀ + e₁ = e binds the two branches together — the prover cannot simulate both branches because they cannot predict e before committing to A₀, B₀, A₁, B₁.

---

## 3. Proof That a Vector Sums to Exactly 1

### 3.1 Problem Statement

The party selection vector is (m₁, m₂, ..., m_N) where N is the number of parties. Each m_i ∈ {0, 1} (proven by the binary proof above). We must additionally prove that exactly one element is 1:

```
m₁ + m₂ + ... + m_N = 1
```

### 3.2 Homomorphic Aggregation

Exponential ElGamal is additively homomorphic. Given ciphertexts Enc(m_i; r_i) = (r_i·G, r_i·H + m_i·G), compute the component-wise sum:

```
(C₁_sum, C₂_sum) = (Σ r_i·G, Σ r_i·H + Σ m_i·G)
                  = ((Σ r_i)·G, (Σ r_i)·H + (Σ m_i)·G)
                  = Enc(Σ m_i; Σ r_i)
```

In group notation (additive Ristretto255):

```
C₁_sum = C₁_1 + C₁_2 + ... + C₁_N
C₂_sum = C₂_1 + C₂_2 + ... + C₂_N
```

This yields an encryption of the sum S = Σ m_i with combined randomness R = Σ r_i (mod q).

### 3.3 Chaum-Pedersen Equality Proof (Sum = 1)

We need to prove that (C₁_sum, C₂_sum) encrypts the value 1. That is:

```
C₂_sum - G = R·H    where R = Σ r_i
```

This is a standard Chaum-Pedersen proof of discrete log equality:

```
DLOG_G(C₁_sum) = DLOG_H(C₂_sum - G) = R
```

**Prover** (knows R = Σ r_i):

```
STEP 1 — Commitment:
    Choose random k ∈ Z_q
    A = k·G
    B = k·H

STEP 2 — Challenge:
    e = H_hash("otvoren-vot.ballot-sum-proof" || C₁_sum || C₂_sum || A || B)

STEP 3 — Response:
    z = k + e·R (mod q)
```

Proof: π_sum = (A, B, z)

**Verifier:**

```
1. Recompute:
   e = H_hash("otvoren-vot.ballot-sum-proof" || C₁_sum || C₂_sum || A || B)

2. Check:
   z·G = A + e·C₁_sum
   z·H = B + e·(C₂_sum - G)
```

Both equations must hold.

---

## 4. Candidate Validity Proof

### 4.1 Problem Statement

For each party p (p = 1, ..., N_parties), the voter submits a candidate preference vector:

```
(c_{p,1}, c_{p,2}, ..., c_{p,K_p})
```

where K_p is the number of candidates in party p. The constraints are:

1. **Each element is binary:** c_{p,j} ∈ {0, 1} for all p, j (proven with binary proofs from Section 2).
2. **Each candidate vector sums to 0 or 1:** Σ_j c_{p,j} ∈ {0, 1}. The voter either does not express a preference for any candidate in this party (sum = 0) or selects exactly one (sum = 1).
3. **Conditional constraint:** If the party vote m_p = 0 (voter did not select party p), then the candidate vector for party p must sum to 0. If m_p = 1, the candidate vector may sum to 0 or 1.

### 4.2 Sum-is-0-or-1 Proof

For each party p's candidate vector, compute the homomorphic sum of the encrypted candidate elements:

```
(C₁_cand_sum, C₂_cand_sum) = Σ_j Enc(c_{p,j}; r_{p,j})
                             = Enc(Σ_j c_{p,j}; Σ_j r_{p,j})
```

Let S_p = Σ_j c_{p,j} and R_p = Σ_j r_{p,j}.

This is a proof that S_p ∈ {0, 1}, which is the exact same disjunctive Chaum-Pedersen structure as Section 2, applied to the aggregate ciphertext (C₁_cand_sum, C₂_cand_sum). Use domain separator `"otvoren-vot.candidate-sum-01-proof"`.

### 4.3 Conditional Consistency Proof

We must prove: if m_p = 0, then S_p = 0.

Equivalently: m_p = 0 implies S_p = 0, which is the same as: S_p ≤ m_p (since both are in {0, 1}).

This can be expressed as: **m_p - S_p ∈ {0, 1}**. That is, the difference between the party selection and the candidate sum is either 0 (both selected) or 1 (party selected but no candidate preference) or the party was not selected and neither was any candidate (0 - 0 = 0).

Wait — let us be precise. The valid combinations are:

| m_p | S_p | Valid? |
|-----|-----|--------|
| 0   | 0   | Yes — party not selected, no candidate preference |
| 0   | 1   | **No** — cannot prefer a candidate without selecting the party |
| 1   | 0   | Yes — party selected, no candidate preference |
| 1   | 1   | Yes — party selected, one candidate preferred |

So the constraint is: (m_p, S_p) ∈ {(0,0), (1,0), (1,1)}, which is equivalent to m_p - S_p ∈ {0, 1} AND m_p ∈ {0, 1} AND S_p ∈ {0, 1}.

Since m_p ∈ {0,1} and S_p ∈ {0,1} are already proven, we only need to additionally prove m_p - S_p ∈ {0, 1}.

**Construction:** Compute the homomorphic difference ciphertext:

```
(C₁_diff, C₂_diff) = Enc(m_p; r_p) - Enc(S_p; R_p)
                    = ((r_p - R_p)·G, (r_p - R_p)·H + (m_p - S_p)·G)
```

In additive group notation:

```
C₁_diff = C₁_party_p - C₁_cand_sum
C₂_diff = C₂_party_p - C₂_cand_sum
```

where (C₁_party_p, C₂_party_p) is the encryption of m_p.

The prover knows the combined randomness r_diff = r_p - R_p and the plaintext difference d = m_p - S_p ∈ {0, 1}.

Apply the disjunctive Chaum-Pedersen proof from Section 2 to (C₁_diff, C₂_diff) to prove d ∈ {0, 1}. Use domain separator `"otvoren-vot.candidate-consistency-proof"`.

### 4.4 Optimization — Only Non-Selected Parties

For parties the voter did NOT select (m_p = 0), the candidate sum must be 0. Rather than using the general conditional proof for all N parties, we can observe:

- For the selected party (m_p = 1): the sum-is-0-or-1 proof (Section 4.2) is sufficient. The conditional proof would show d = m_p - S_p ∈ {0,1}, which is always true when m_p = 1.
- For non-selected parties (m_p = 0): the sum-is-0-or-1 proof already restricts S_p ∈ {0,1}. The conditional proof restricts d = 0 - S_p ∈ {0,1}, which forces S_p = 0.

However, this optimization leaks which party was selected (the conditional proof is omitted for exactly one party). Since the ballot is encrypted and the proofs are zero-knowledge, the verifier learns nothing about which party was selected from the proof structure alone — **but the optimization changes the proof structure per party, creating a side channel.**

Therefore: **apply the conditional consistency proof uniformly to ALL parties.** The proof for the selected party will prove d ∈ {0,1} honestly (with d = 0 or d = 1); the proofs for non-selected parties will prove d ∈ {0,1} honestly (with d = 0). The verifier sees the same proof structure for every party.

---

## 5. Proof Sizes

### 5.1 Element Sizes in Ristretto255

| Element | Size |
|---------|------|
| Ristretto255 group point (compressed) | 32 bytes |
| Scalar (Z_q) | 32 bytes |

### 5.2 Per-Proof Sizes

**Binary proof (Section 2) — disjunctive Chaum-Pedersen:**

```
π_binary = (A₀, B₀, A₁, B₁, e₀, e₁, z₀, z₁)
         = 4 points + 4 scalars
         = 4 × 32 + 4 × 32
         = 256 bytes
```

Note: e₀ can be omitted and recomputed from e and e₁ (since e₀ = e - e₁), saving 32 bytes:

```
π_binary_optimized = (A₀, B₀, A₁, B₁, e₁, z₀, z₁)
                   = 4 points + 3 scalars
                   = 4 × 32 + 3 × 32
                   = 224 bytes
```

**Sum-equals-1 proof (Section 3) — standard Chaum-Pedersen:**

```
π_sum = (A, B, z)
      = 2 points + 1 scalar
      = 2 × 32 + 1 × 32
      = 96 bytes
```

**Candidate sum-is-0-or-1 proof (Section 4.2):** Same as binary proof = 224 bytes (optimized).

**Conditional consistency proof (Section 4.3):** Same as binary proof = 224 bytes (optimized).

### 5.3 Per-Ballot Total

Let:
- N = number of parties (max 50)
- K_p = number of candidates in party p (max 50 each)
- K_total = Σ K_p = total candidate slots (max 2500)

**Ciphertext data:**

```
Ciphertext per element: 2 × 32 = 64 bytes
Party vector: N × 64 bytes
Candidate vectors: K_total × 64 bytes
Total ciphertext: (N + K_total) × 64 bytes
```

**Proof data:**

| Proof | Count | Size each | Total |
|-------|-------|-----------|-------|
| Binary proof (party elements) | N | 224 B | 224N bytes |
| Binary proof (candidate elements) | K_total | 224 B | 224 × K_total bytes |
| Party sum = 1 | 1 | 96 B | 96 bytes |
| Candidate sum ∈ {0,1} per party | N | 224 B | 224N bytes |
| Conditional consistency per party | N | 224 B | 224N bytes |

```
Total proof bytes = 224N + 224·K_total + 96 + 224N + 224N
                  = 672N + 224·K_total + 96
```

**Worst case (N = 50, K_total = 2500):**

```
Ciphertext: (50 + 2500) × 64 = 163,200 bytes ≈ 159 KB
Proofs:     672 × 50 + 224 × 2500 + 96 = 33,600 + 560,000 + 96 = 593,696 bytes ≈ 580 KB
Total:      ≈ 739 KB per ballot
```

**Typical case (N = 30, K_total = 600):**

```
Ciphertext: (30 + 600) × 64 = 40,320 bytes ≈ 39 KB
Proofs:     672 × 30 + 224 × 600 + 96 = 20,160 + 134,400 + 96 = 154,656 bytes ≈ 151 KB
Total:      ≈ 190 KB per ballot
```

---

## 6. Verification Costs

### 6.1 Point Multiplications per Proof Verification

The dominant cost in verification is scalar-point multiplication (scalar × group element). Point additions are negligible in comparison.

**Binary proof verification (Section 2.3):**
- Recompute e: 1 hash (negligible vs. point mults)
- Check `z₀·G = A₀ + e₀·C₁`: 2 scalar mults (z₀·G and e₀·C₁), 1 point add
- Check `z₀·H = B₀ + e₀·C₂`: 2 scalar mults, 1 point add
- Check `z₁·G = A₁ + e₁·C₁`: 2 scalar mults, 1 point add
- Check `z₁·H = B₁ + e₁·(C₂ - G)`: 2 scalar mults, 1 point sub, 1 point add
- **Total: 8 scalar multiplications** per binary proof

Using multi-scalar multiplication (Straus/Pippenger), each 2-term check can be done in ~1.5× the cost of a single scalar mult. Effective cost: ~6 scalar mults.

**Sum-equals-1 proof verification (Section 3.3):**
- Check `z·G = A + e·C₁_sum`: 2 scalar mults
- Check `z·H = B + e·(C₂_sum - G)`: 2 scalar mults
- **Total: 4 scalar multiplications** (effective ~3 with multi-scalar mult)

**Candidate sum-is-0-or-1 proof:** Same as binary proof = 8 (effective ~6) scalar mults.

**Conditional consistency proof:** Same as binary proof = 8 (effective ~6) scalar mults.

### 6.2 Per-Ballot Verification Cost

| Proof | Count | Scalar mults each (effective) | Total |
|-------|-------|-------------------------------|-------|
| Binary (party) | N | 6 | 6N |
| Binary (candidate) | K_total | 6 | 6 × K_total |
| Sum = 1 | 1 | 3 | 3 |
| Candidate sum ∈ {0,1} | N | 6 | 6N |
| Conditional consistency | N | 6 | 6N |

```
Total scalar mults per ballot = 18N + 6·K_total + 3
```

**Worst case (N = 50, K_total = 2500):**

```
18 × 50 + 6 × 2500 + 3 = 900 + 15,000 + 3 = 15,903 scalar mults
```

**Typical case (N = 30, K_total = 600):**

```
18 × 30 + 6 × 600 + 3 = 540 + 3,600 + 3 = 4,143 scalar mults
```

### 6.3 Total System Verification Cost

A Ristretto255 scalar multiplication takes approximately 50 microseconds on modern hardware (single core, no batching).

**Worst case — 4 million ballots, N = 50, K_total = 2500:**

```
Total scalar mults = 4,000,000 × 15,903 = 63,612,000,000 ≈ 6.36 × 10^10

Wall-clock (single core) = 6.36 × 10^10 × 50 × 10^-6 s
                         = 3,180,600 s
                         ≈ 36.8 days (single core)

With 64 cores: ≈ 13.8 hours
With batch verification optimization (2× speedup): ≈ 6.9 hours
```

**Typical case — 4 million ballots, N = 30, K_total = 600:**

```
Total scalar mults = 4,000,000 × 4,143 = 16,572,000,000 ≈ 1.66 × 10^10

Wall-clock (single core) = 1.66 × 10^10 × 50 × 10^-6 s
                         = 828,600 s
                         ≈ 9.6 days (single core)

With 64 cores: ≈ 3.6 hours
With batch verification optimization (2× speedup): ≈ 1.8 hours
```

These estimates confirm that delegated verifiers (political parties, NGOs) with a modern 64-core server can verify all ballot proofs within a few hours.

---

## 7. Batching Optimization

### 7.1 Problem

Client-side proof generation must complete within the 5-second budget (see design spec Section 2.3). In the worst case (2550 encrypted elements), the client must generate:

```
2550 binary proofs + 1 sum proof + 50 candidate-sum proofs + 50 conditional proofs
= 2651 Sigma proofs
```

Each Sigma proof requires ~2 scalar multiplications for commitment generation plus ~1 for the response. At ~100 microseconds per scalar mult in WASM (approximately 2x slower than native), this is:

```
2651 × 3 × 100 μs ≈ 795 ms
```

This is within budget for a mid-range laptop (likely well under 2 seconds even in WASM). However, if future elections have larger ballots or if low-end devices are supported, batching may be needed.

### 7.2 Batch Sigma Protocol

When multiple Sigma proofs share the same algebraic structure (e.g., all binary proofs have the same verification equations with different inputs), they can share a single challenge via a batched Fiat-Shamir transform.

**Standard (unbatched):** Each proof i has its own challenge e_i = H(x_i || A_i).

**Batched:** All proofs of the same type share one challenge:

```
e = H("otvoren-vot.batch-binary-proof" || x₁ || A₁ || x₂ || A₂ || ... || x_n || A_n)
```

Each proof i then uses challenge e_i = e · ρ_i, where ρ_i is a deterministic per-proof randomizer:

```
ρ_i = H("otvoren-vot.batch-randomizer" || e || i)
```

This prevents a malicious prover from exploiting the shared challenge to shift errors between proofs.

**Savings:** Instead of n hash computations, we compute 1 hash (large input) + n small hashes for randomizers. The dominant savings is in reducing the number of random nonces that must be generated (one set of nonces per proof type rather than per element).

### 7.3 Batch Verification (Server/Verifier Side)

Independent of client-side batching, verifiers can batch-verify multiple proofs:

Given n proofs to verify, each with verification equation of the form `z_i·G = A_i + e_i·X_i`:

1. Choose random weights w₁, ..., w_n ∈ Z_q
2. Check a single combined equation:

```
(Σ w_i·z_i)·G = Σ w_i·A_i + Σ (w_i·e_i)·X_i
```

This collapses n verification equations into 1 multi-scalar multiplication, yielding approximately 2× speedup over individual verification (the multi-scalar mult of n terms costs roughly n/2 individual scalar mults via Pippenger's algorithm).

If the combined equation fails, fall back to individual verification to identify which proof(s) are invalid.

### 7.4 Practical Recommendation

For the current parameter range (N ≤ 50, K_total ≤ 2500):

- **Client-side:** Individual proof generation is likely within budget. Implement unbatched proofs first. Benchmark on target devices. If the 5-second budget is exceeded, switch to batched proofs for binary proofs (the dominant count).
- **Server-side (bulletin board validation):** Use batch verification. Each incoming ballot's proofs are batch-verified in a single multi-scalar multiplication.
- **Delegated verifiers:** Use batch verification across all ballots. This is what makes full verification of 4M ballots feasible in hours rather than days.

---

## 8. Implementation Notes

### 8.1 Nonce Generation

All random nonces (k values in Sigma protocol commitments) MUST be generated using a cryptographically secure random number generator:

- **Browser (TypeScript):** `crypto.getRandomValues()` to fill a 32-byte buffer, then reduce modulo q using libsodium's `crypto_core_ristretto255_scalar_random()`.
- **Server (Go):** `crypto/rand.Read()` or `filippo.io/edwards25519` scalar random functions.

**Nonce reuse is catastrophic.** If the same nonce k is used in two different proofs, the secret witness (randomness r or message m) can be extracted from the two transcripts.

### 8.2 Serialization

Proofs are serialized as concatenated fixed-size byte arrays. No length prefixes or delimiters are needed because all elements have known, fixed sizes (32 bytes each for both points and scalars in Ristretto255).

```
Binary proof (224 bytes):
  [A₀: 32][B₀: 32][A₁: 32][B₁: 32][e₁: 32][z₀: 32][z₁: 32]

Sum proof (96 bytes):
  [A: 32][B: 32][z: 32]
```

### 8.3 Proof Ordering in Ballot Submission

The ballot submission payload contains proofs in a canonical order:

```json
{
  "ballot_id": "<base64url, 256-bit>",
  "party_ciphertexts": [ [C₁, C₂], ... ],
  "party_binary_proofs": [ π_binary, ... ],
  "party_sum_proof": π_sum,
  "candidate_ciphertexts": {
    "party_0": [ [C₁, C₂], ... ],
    "party_1": [ [C₁, C₂], ... ],
    ...
  },
  "candidate_binary_proofs": {
    "party_0": [ π_binary, ... ],
    ...
  },
  "candidate_sum_proofs": [ π_01, ... ],
  "conditional_proofs": [ π_cond, ... ]
}
```

All group elements and scalars are encoded as 32-byte little-endian arrays, then base64url-encoded for JSON transport.
