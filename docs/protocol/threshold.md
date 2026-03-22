# Threshold Key Management and Decryption

**System:** otvoren-vot — End-to-end verifiable e-voting for Bulgarian national elections
**Group:** Ristretto255 (prime-order group over Curve25519, order q ≈ 2^252)
**Encryption:** Exponential ElGamal
**Threshold:** 5-of-9 (t = 5, n = 9)
**HSM:** FIPS 140-3 Level 3 (e.g., YubiHSM 2, Nitrokey HSM 2)

---

## 1. Feldman's Verifiable Secret Sharing

Feldman's VSS allows a dealer to distribute shares of a secret to n parties such that any t parties can reconstruct the secret, while each party can independently verify the correctness of their share.

### 1.1 Setup

Let G be the Ristretto255 base point. The dealer holds a secret a₀ ∈ Z_q and wants to create a (t, n)-threshold sharing.

**Dealer's polynomial:** Choose random coefficients a₁, a₂, ..., a_{t-1} ∈ Z_q and define:

```
f(x) = a₀ + a₁·x + a₂·x² + ... + a_{t-1}·x^{t-1}  (mod q)
```

The secret is a₀ = f(0).

### 1.2 Share Distribution

For each trustee i ∈ {1, 2, ..., n}, the dealer computes and sends (via a secure, authenticated channel):

```
s_i = f(i) = a₀ + a₁·i + a₂·i² + ... + a_{t-1}·i^{t-1}  (mod q)
```

### 1.3 Public Commitments

The dealer publishes commitments to each polynomial coefficient:

```
C_j = a_j · G    for j = 0, 1, ..., t-1
```

These are Ristretto255 group elements. C₀ = a₀·G is the commitment to the secret (which will become the public key contribution from this dealer).

### 1.4 Share Verification

Each trustee i verifies their share s_i against the public commitments:

```
s_i · G = Σ_{j=0}^{t-1} i^j · C_j
```

Expanded:

```
s_i · G = C₀ + i·C₁ + i²·C₂ + ... + i^{t-1}·C_{t-1}
```

The left side is a single scalar-point multiplication. The right side is a multi-scalar multiplication with t terms, where the scalars are known public values (powers of i) and the points are the published commitments.

If this equation holds, trustee i is assured that their share is consistent with the published commitments. If it fails, trustee i broadcasts a complaint, and the dealer must reveal the share for verification (or be disqualified).

---

## 2. Distributed Key Generation (DKG)

The DKG protocol ensures that no single party ever knows the election secret key. Each of the 9 trustees simultaneously acts as a dealer in Feldman's VSS, and the final election key is the combination of all individual contributions.

### 2.1 Protocol Steps

**Round 1 — Polynomial generation and commitment:**

Each trustee k (k = 1, ..., 9) independently:

1. Generates a random polynomial f_k(x) of degree t-1 = 4 inside their HSM:

```
f_k(x) = a_{k,0} + a_{k,1}·x + a_{k,2}·x² + a_{k,3}·x³ + a_{k,4}·x⁴  (mod q)
```

2. Publishes commitments to their polynomial coefficients:

```
C_{k,j} = a_{k,j} · G    for j = 0, 1, 2, 3, 4
```

3. Computes shares for every other trustee i:

```
s_{k→i} = f_k(i)    for i = 1, ..., 9
```

4. Sends s_{k→i} to trustee i via a secure, authenticated channel (TLS with mutual authentication, or in-person during the DKG ceremony).

**Round 2 — Share verification:**

Each trustee i receives shares s_{1→i}, s_{2→i}, ..., s_{9→i} from all 9 dealers (including their own). For each received share s_{k→i}, trustee i verifies:

```
s_{k→i} · G = Σ_{j=0}^{4} i^j · C_{k,j}
```

If verification fails for share from dealer k, trustee i broadcasts a complaint. The complaint is resolved publicly:
- Dealer k reveals s_{k→i} in public.
- All parties verify the revealed share against the commitments.
- If the revealed share is inconsistent with the commitments, dealer k is disqualified: all their contributions are excluded, and the protocol continues with 8 trustees (threshold remains 5).

**Round 3 — Share combination:**

Each trustee i computes their final combined share:

```
S_i = Σ_{k=1}^{9} s_{k→i} = Σ_{k=1}^{9} f_k(i)  (mod q)
```

This is the trustee's share of the combined secret. The combined secret is:

```
S = Σ_{k=1}^{9} a_{k,0} = Σ_{k=1}^{9} f_k(0)  (mod q)
```

No single party computes or knows S. Each trustee i only knows S_i.

### 2.2 Election Public Key

The election public key is:

```
H = S · G = (Σ_{k=1}^{9} a_{k,0}) · G = Σ_{k=1}^{9} C_{k,0}
```

This is computed by anyone from the published commitments — no secret information is needed. It is the sum of the first commitments from all dealers.

### 2.3 Public Share Verification Keys

Each trustee i's public share verification key (used later to verify partial decryptions) is:

```
H_i = S_i · G
```

This can also be computed from the published commitments by anyone:

```
H_i = Σ_{k=1}^{9} (Σ_{j=0}^{4} i^j · C_{k,j})
    = Σ_{j=0}^{4} i^j · (Σ_{k=1}^{9} C_{k,j})
```

Define the combined commitments:

```
C̄_j = Σ_{k=1}^{9} C_{k,j}    for j = 0, 1, 2, 3, 4
```

Then:

```
H_i = Σ_{j=0}^{4} i^j · C̄_j
```

And H = C̄₀ is the election public key.

### 2.4 Security Properties

- **Secrecy:** Any coalition of fewer than t = 5 trustees learns nothing about S beyond the public key H. Information-theoretically secure (not computationally — the DKG leaks C̄_j commitments, but these are in the group, not the scalar field).
- **Robustness:** The protocol tolerates up to 4 byzantine trustees (they can be disqualified but cannot prevent key generation, as long as at least 5 honest trustees remain).
- **Verifiability:** Any observer can verify the DKG transcript — all commitments are public, and the resulting H and H_i values are deterministic from the commitments.

---

## 3. Key Lifecycle

### 3.1 Generation (DKG Ceremony)

- **Timing:** Weeks before election day.
- **Location:** Secure facility, access-controlled, witnessed, video-recorded.
- **Participants:** 9 trustees from adversarial institutions (e.g., CIK officials, political party representatives, civil society organizations, judiciary representatives, academic cryptographers).
- **Equipment:** Each trustee brings their own HSM. A ceremony workstation coordinates the protocol.
- **Process:** The DKG protocol (Section 2) is executed. All commitments are published. Each trustee verifies their share inside their HSM. The election public key H is computed and published.
- **Output:**
  - Election public key H (public)
  - 9 sets of polynomial commitments C_{k,j} (public)
  - 9 combined share verification keys H_i (public)
  - Each trustee's HSM contains their private share S_i (never exported)

### 3.2 Distribution

The election public key H is published through multiple independent channels to prevent substitution attacks:

1. **Bulletin board** — embedded in the election configuration record
2. **CIK website** — published as a signed announcement
3. **Political party websites** — each party independently publishes the key they witnessed during the ceremony
4. **Print media** — the key (in base64 or hex) published in the official gazette
5. **Web application** — embedded in the client-side code (hash-verifiable via reproducible build)

Any discrepancy between channels indicates tampering. The key is 32 bytes (Ristretto255 compressed point), easily printed and compared.

### 3.3 Compromise Response (Proactive Re-sharing)

If a trustee's HSM is compromised or lost between the DKG ceremony and election day, the remaining trustees can re-share to exclude the compromised share **without changing the election public key**.

**Proactive secret sharing protocol:**

Let trustee m be compromised. The remaining n-1 = 8 trustees execute:

1. Each surviving trustee k generates a new random polynomial g_k(x) of degree t-1 = 4 with g_k(0) = 0 (the zero-secret polynomial):

```
g_k(x) = b_{k,1}·x + b_{k,2}·x² + b_{k,3}·x³ + b_{k,4}·x⁴  (mod q)
```

Note: The constant term is 0. This ensures the combined secret S does not change.

2. Each surviving trustee k publishes commitments:

```
D_{k,j} = b_{k,j} · G    for j = 1, 2, 3, 4
```

And implicitly D_{k,0} = O (the identity point), since b_{k,0} = 0.

3. Each surviving trustee k sends shares g_k(i) to every other surviving trustee i (excluding m).

4. Each surviving trustee i verifies received shares against commitments.

5. Each surviving trustee i updates their share:

```
S_i' = S_i + Σ_{k ≠ m} g_k(i)  (mod q)
```

The new shares S_i' are shares of the same secret S (since Σ g_k(0) = 0 for all k), but trustee m's old share S_m is no longer consistent with the new sharing polynomial.

6. Trustee m is excluded from the trustee set. If the number of remaining uncompromised trustees drops below t = 5, a full new DKG must be performed (with a new election public key, requiring re-publication).

### 3.4 Validity Period

The election public key and all associated shares are valid for **one election only**. They are never reused across elections, even if the same trustees are appointed.

### 3.5 Destruction

After the election results are certified and all legal challenge periods expire:

1. All 9 trustees (or as many as are available) convene at a witnessed ceremony.
2. Each trustee inserts their HSM into a workstation.
3. The HSM's secure storage is wiped using the manufacturer's key destruction command (e.g., `yubihsm-shell put-opaque` overwrite + factory reset, or PKCS#11 `C_DestroyObject` followed by device zeroization).
4. The wipe operation is performed on camera.
5. A signed destruction log is produced, recording: trustee identity, HSM serial number, timestamp, destruction command output, witness signatures.
6. HSMs are physically returned to their respective institutions or securely destroyed.

---

## 4. Threshold Decryption

### 4.1 Partial Decryption

Given a ciphertext (C₁, C₂) = (r·G, r·H + m·G) and a trustee i with private share S_i, the trustee computes a **partial decryption**:

```
D_i = S_i · C₁
```

This computation is performed entirely inside the HSM. The HSM receives C₁ as input and returns D_i as output. The private share S_i never leaves the HSM.

**What D_i represents:** Since C₁ = r·G, we have D_i = S_i·r·G = r·(S_i·G) = r·H_i, where H_i = S_i·G is the trustee's public share verification key.

### 4.2 Proof of Correct Partial Decryption

Each trustee must prove that their partial decryption D_i is honestly computed — that is, D_i = S_i · C₁ for the same S_i whose public counterpart is H_i = S_i · G.

This is a **Chaum-Pedersen proof of discrete log equality:**

```
DLOG_G(H_i) = DLOG_{C₁}(D_i) = S_i
```

The prover (HSM) knows S_i and must prove that the same scalar relates (G, H_i) and (C₁, D_i).

**Prover** (HSM, knows S_i):

```
STEP 1 — Commitment:
    Choose random k ∈ Z_q (generated inside HSM)
    A = k · G
    B = k · C₁

STEP 2 — Challenge (Fiat-Shamir):
    e = H_hash("otvoren-vot.partial-decryption-proof" || G || H_i || C₁ || D_i || A || B)

STEP 3 — Response:
    z = k + e · S_i  (mod q)
```

Proof: π_dec_i = (A, B, z)

The HSM outputs (D_i, π_dec_i). The private share S_i was used inside the HSM for the computation but never appears in the output.

**Verifier** (anyone, given G, H_i, C₁, D_i, and proof π_dec_i = (A, B, z)):

```
1. Recompute challenge:
   e = H_hash("otvoren-vot.partial-decryption-proof" || G || H_i || C₁ || D_i || A || B)

2. Check:
   z · G  = A + e · H_i
   z · C₁ = B + e · D_i
```

Both equations must hold. The first ensures z = k + e·S_i for some k, with S_i being the discrete log of H_i. The second ensures the same S_i was used to compute D_i from C₁.

### 4.3 Decryption During the Ceremony

During the televised ceremony, each of the 5+ participating trustees performs the following for **every tally ciphertext** (encrypted sum for each party slot and each candidate slot):

For each tally ciphertext (C₁^(j), C₂^(j)), j = 1, ..., M (where M is the number of tally slots):

1. HSM receives C₁^(j) as input.
2. HSM computes D_i^(j) = S_i · C₁^(j) and generates proof π_dec_i^(j).
3. HSM outputs (D_i^(j), π_dec_i^(j)).

The Tally Service displays verification results for each proof on the ceremony screen in real-time.

**Performance per trustee:** Each tally slot requires 1 scalar multiplication (for D_i) + 2 scalar multiplications (for the proof commitment) + 1 scalar multiplication and 1 scalar multiply-add (for the response) = approximately 4 scalar multiplications inside the HSM. For M = 2550 tally slots (worst case):

```
2550 × 4 = 10,200 scalar multiplications
```

At ~200 μs per scalar mult on a YubiHSM 2 (conservative estimate for HSM-internal operations):

```
10,200 × 200 μs ≈ 2.04 seconds per trustee
```

With overhead for USB communication and proof serialization, estimate 5-10 seconds per trustee. For 5 trustees sequentially: 25-50 seconds total.

---

## 5. Share Combination (Lagrange Interpolation in the Exponent)

### 5.1 Lagrange Coefficients

Given a set T of t participating trustees (|T| = t = 5), the Lagrange interpolation coefficient for trustee i ∈ T evaluated at x = 0 is:

```
λ_i = Π_{j ∈ T, j ≠ i} (0 - j) / (i - j)  (mod q)
    = Π_{j ∈ T, j ≠ i} (-j) / (i - j)  (mod q)
    = Π_{j ∈ T, j ≠ i} j / (j - i)  (mod q)
```

These coefficients satisfy the interpolation identity: for any polynomial f of degree < t,

```
f(0) = Σ_{i ∈ T} λ_i · f(i)
```

### 5.2 Computing Lagrange Coefficients

For the 5-of-9 threshold with trustee indices from {1, 2, ..., 9}, the coefficients are computed over Z_q.

**Example:** If T = {1, 3, 5, 7, 9} (trustees 1, 3, 5, 7, 9 participate):

```
λ₁ = (3·5·7·9) / ((3-1)·(5-1)·(7-1)·(9-1))
   = 945 / (2·4·6·8)
   = 945 / 384
   = 945 · 384⁻¹  (mod q)
```

Division is computed as multiplication by the modular inverse: 384⁻¹ mod q.

Similarly for λ₃, λ₅, λ₇, λ₉. All arithmetic is modular over Z_q.

### 5.3 Combining Partial Decryptions

Given t partial decryptions D_i (one per participating trustee i ∈ T), compute the combined decryption:

```
D = Σ_{i ∈ T} λ_i · D_i
```

This is a multi-scalar multiplication: the scalars are the Lagrange coefficients λ_i, and the points are the partial decryptions D_i.

**Why this works:** Each D_i = S_i · C₁ = S_i · r · G. So:

```
D = Σ_{i ∈ T} λ_i · S_i · r · G
  = r · (Σ_{i ∈ T} λ_i · S_i) · G
  = r · S · G                        (by Lagrange interpolation: Σ λ_i·S_i = S = f(0))
  = S · C₁
  = r · H
```

### 5.4 Recovering the Plaintext

Given the combined decryption D and the ciphertext (C₁, C₂):

```
m · G = C₂ - D
```

Since C₂ = r·H + m·G and D = r·H:

```
C₂ - D = r·H + m·G - r·H = m·G
```

We now have the point m·G and need to recover the scalar m.

### 5.5 Solving the Discrete Logarithm (Baby-Step Giant-Step)

For tally ciphertexts, m is the sum of votes — a value in the range [0, N_voters] where N_voters ≤ 4,000,000.

**Baby-Step Giant-Step (BSGS):**

Let n = ⌈√N_voters⌉ ≈ 2000.

```
PRECOMPUTATION (baby steps):
    Build a hash table: { j·G → j } for j = 0, 1, 2, ..., n-1

SEARCH (giant steps):
    Let P = m·G (the target point)
    Let Δ = (-n)·G (the giant step)
    For i = 0, 1, 2, ..., n-1:
        Check if P + i·Δ is in the hash table
        If P + i·Δ = j·G, then m = j + i·n
        Return m
```

**Complexity:**
- Time: O(√N_voters) ≈ 2000 point additions + hash lookups
- Space: O(√N_voters) ≈ 2000 table entries × 32 bytes ≈ 64 KB

**Per tally slot:** Under 1 ms on modern hardware.
**All 2550 tally slots:** Under 3 seconds.

The BSGS table can be precomputed once and reused for all tally slots (since the base point G is the same). Total precomputation: ~2000 scalar multiplications ≈ 0.1 seconds.

---

## 6. HSM Interface

### 6.1 PKCS#11 Operations Required

The HSM must support the following minimum set of PKCS#11 operations for the otvoren-vot protocol. The HSM is treated as a black box that stores a Ristretto255 scalar (the trustee's share) and performs scalar-point multiplications on demand.

| PKCS#11 Operation | Protocol Usage | Description |
|-------------------|----------------|-------------|
| `C_GenerateKeyPair` | DKG (Section 2) | Generate the trustee's polynomial coefficients a_{k,j} as private keys inside the HSM. The corresponding public commitments C_{k,j} = a_{k,j}·G are exported. |
| `C_DeriveKey` | DKG share computation | Evaluate the polynomial f_k(i) for each other trustee i. The HSM computes the share internally using its stored coefficients and exports the share value (sent to trustee i via secure channel). |
| `C_Sign` | Partial decryption (Section 4) | Compute D_i = S_i · C₁. The HSM receives C₁ (a group element) as the "message" and performs scalar-point multiplication with the stored share S_i. Also generates the Chaum-Pedersen proof nonce k, computes A = k·G and B = k·C₁, and the response z = k + e·S_i. The proof generation MUST happen inside the HSM to prevent side-channel leakage of S_i. |
| `C_Verify` | Share verification | Verify received shares from other dealers during DKG. The HSM can perform the verification equation check for incoming shares. |
| `C_DestroyObject` | Key destruction (Section 3.5) | Securely erase the stored private share. Must perform cryptographic erasure (overwrite with random data, then zeroize). |

### 6.2 Key Storage Requirements

The HSM must store:

| Object | Type | Size | Lifetime |
|--------|------|------|----------|
| Polynomial coefficients a_{k,0}, ..., a_{k,4} | Private scalars | 5 × 32 = 160 bytes | DKG ceremony only (destroyed after share distribution) |
| Combined share S_i | Private scalar | 32 bytes | DKG through post-election destruction |
| Public share verification key H_i | Public point | 32 bytes | Convenience; can be recomputed from public data |

After the DKG ceremony completes and all shares are verified, the individual polynomial coefficients a_{k,j} can be destroyed. Only the combined share S_i needs to persist until the election is complete.

### 6.3 HSM Security Requirements

- **FIPS 140-3 Level 3** certification minimum (physical tamper resistance, identity-based authentication).
- **Key non-exportability:** The HSM must be configured so that the private share S_i cannot be extracted via any command, backup, or firmware operation. The share must be generated, used, and destroyed entirely within the HSM boundary.
- **Authentication:** PIN or biometric authentication before any cryptographic operation. Lockout after 3 failed attempts (configurable).
- **Audit logging:** The HSM should log all cryptographic operations (timestamps, operation types) to its internal tamper-evident log.
- **Side-channel resistance:** The HSM must implement constant-time scalar multiplication to prevent timing attacks.

### 6.4 Implementation Notes for Specific HSMs

**YubiHSM 2:**
- Supports Ed25519 key generation and signing natively.
- Ristretto255 scalar multiplication can be implemented via the Ed25519 sign operation: encode C₁ as an Ed25519 point, use the stored key for scalar multiplication, and decode the result. Requires careful handling of the Ristretto255 encoding/decoding.
- Alternatively, use the HMAC-SHA256 wrap/unwrap feature to store the share as an opaque secret and perform the scalar multiplication in software after unwrapping — but this defeats the purpose of HSM key protection. **The scalar mult MUST happen inside the HSM.**

**Nitrokey HSM 2 (SmartCard-HSM):**
- Based on the SmartCard-HSM applet. Supports ECDSA and ECDH on various curves.
- Curve25519/Ristretto255 support may require custom firmware or a firmware update. Verify compatibility before procurement.

**Generic PKCS#11 wrapper:**
- Implement a Go PKCS#11 wrapper (`github.com/miekg/pkcs11` or equivalent) that abstracts HSM-specific quirks.
- The wrapper exposes three operations to the Tally Service: `GenerateDKGPolynomial()`, `ComputePartialDecryption(C₁) → (D_i, proof)`, and `DestroyShare()`.

---

## 7. 5-of-9 Threshold Parameters

### 7.1 Parameter Choice Rationale

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| n (total trustees) | 9 | Maps to 9 adversarial institutions: diverse representation from government, judiciary, political parties, civil society, academia |
| t (threshold) | 5 | Simple majority of trustees |
| Fault tolerance | 4 | Up to 4 trustees can be absent, refuse to participate, or have failed HSMs without preventing decryption |
| Collusion resistance | 5 | At least 5 trustees must collude to reconstruct the secret key — requires majority corruption across adversarial institutions |
| Privacy guarantee | 4 | Any coalition of 4 or fewer trustees learns zero information about the secret key (information-theoretic for the secret sharing; computational for the ElGamal encryption) |

### 7.2 Why Not Other Thresholds?

| Alternative | Problem |
|-------------|---------|
| 3-of-9 | Too low collusion resistance — only 3 parties need to conspire. Insufficient for a national election with powerful adversaries. |
| 7-of-9 | Too low fault tolerance — only 2 failures allowed. A single institution boycotting + 1 HSM failure blocks decryption. |
| 5-of-5 | No fault tolerance at all. Any single failure blocks the election. |
| 5-of-7 | Only 2 failures tolerated. 7 institutions may not provide sufficient diversity for Bulgarian political landscape. |
| 5-of-9 | Optimal balance: tolerates 4 failures (robust against logistics problems, boycotts, hardware failures) while requiring majority collusion (5 of 9 adversarial institutions). |

### 7.3 Trustee Selection Criteria

The 9 trustees should be drawn from maximally adversarial institutions — organizations that have conflicting interests, making collusion unlikely:

1. **CIK representative** (Central Election Commission)
2. **Governing coalition representative** (party in power)
3. **Opposition representative** (largest opposition party)
4. **Judiciary representative** (Supreme Administrative Court or Constitutional Court)
5. **Ombudsman's office representative**
6. **Bulgarian Academy of Sciences** (independent academic institution)
7. **Civil society / election monitoring NGO** (e.g., Bulgarian Helsinki Committee)
8. **National Audit Office representative**
9. **Media / journalist union representative**

No two trustees from the same institution. No familial or reporting relationships between trustees. Each trustee is personally responsible for their HSM.

### 7.4 Threshold Arithmetic Summary

For reference, the key mathematical relationships in the 5-of-9 system:

```
Polynomial degree:          t - 1 = 4
Number of coefficients:     t = 5  (per dealer polynomial)
Total polynomials in DKG:   n = 9  (one per trustee)
Total shares distributed:   n² = 81  (each of 9 trustees sends a share to each of 9 trustees)
Total commitments published: n × t = 45  (9 dealers × 5 coefficients each)
Combined commitments:       t = 5  (C̄₀, C̄₁, C̄₂, C̄₃, C̄₄)

Lagrange coefficient computation:
  - Each λ_i requires t-1 = 4 multiplications and 4 modular inversions
  - For 5 participating trustees: 20 multiplications + 20 inversions (negligible)

Share combination (per tally ciphertext):
  - 5-term multi-scalar multiplication: ≈ 3 scalar mults (via Straus's algorithm)

Total decryption (per ciphertext):
  - 5 partial decryptions (inside HSMs): 5 scalar mults
  - 5 proof generations (inside HSMs): ~15 scalar mults
  - 1 share combination: ~3 scalar mults
  - 5 proof verifications: 20 scalar mults
  - 1 BSGS lookup: ~2000 point additions (precomputed table)
```

### 7.5 Failure Mode Analysis

| Trustees available | Can decrypt? | Notes |
|--------------------|-------------|-------|
| 9 | Yes | Ideal case. All contribute. Extra trustees provide redundant verification. |
| 8 | Yes | 1 failure tolerated. |
| 7 | Yes | 2 failures tolerated. |
| 6 | Yes | 3 failures tolerated. |
| 5 | Yes | Minimum viable. 4 failures tolerated. No further margin. |
| 4 | **No** | Decryption impossible. Political crisis. Ceremony rescheduled pending resolution. |
| 3 or fewer | **No** | Decryption impossible. The encrypted votes exist on the bulletin board indefinitely but cannot be tallied. |

In the catastrophic case where fewer than 5 trustees are available, the election results cannot be computed. The encrypted ballots remain on the public bulletin board, cryptographically sealed. This is by design: the system fails safe (no results) rather than failing open (results computed by fewer than a majority of trustees).

---

## 8. End-to-End Protocol Summary

For reference, the complete key lifecycle from generation through destruction:

```
WEEKS BEFORE ELECTION:
  1. DKG ceremony → election public key H published
  2. H distributed via multiple independent channels
  3. Each trustee stores S_i in their HSM

ELECTION DAY:
  4. Voters encrypt ballots with H (client-side)
  5. Encrypted ballots posted to bulletin board
  6. No decryption keys are used during voting

AFTER POLLS CLOSE (CEREMONY):
  7. Tally ciphertexts computed via homomorphic aggregation
  8. Each of 5+ trustees computes partial decryptions inside HSM
  9. Each partial decryption accompanied by Chaum-Pedersen proof
  10. Partial decryptions combined via Lagrange interpolation
  11. Plaintext tallies recovered via BSGS
  12. Results published with all proofs

POST-CERTIFICATION:
  13. HSMs wiped on camera
  14. Destruction logged and signed
  15. Election keys cease to exist
```
