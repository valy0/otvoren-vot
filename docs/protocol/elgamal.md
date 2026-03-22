# Exponential ElGamal over Ristretto255

**System:** otvoren-vot — end-to-end verifiable e-voting for Bulgarian national elections
**Audience:** Developers implementing or auditing the encryption layer

This document specifies the ElGamal encryption scheme used for ballot encryption, homomorphic tallying, and threshold decryption. It is "exponential" ElGamal because the plaintext message is placed in the exponent, enabling additive homomorphism.

---

## 1. Group Notation

Let **G** denote the Ristretto255 group — a prime-order group constructed as a quotient group from Curve25519. Every element of G has a unique canonical 32-byte encoding, and every valid encoding decodes to a unique group element.

| Symbol | Meaning |
|--------|---------|
| `G` | The Ristretto255 prime-order group |
| `g` | A fixed generator of G (the Ristretto255 basepoint) |
| `q` | The group order: `q = 2^252 + 27742317777372353535851937790883648493` |
| `Z_q` | The integers modulo `q` (the scalar field) |
| `g^a` | Scalar multiplication: the group element obtained by "multiplying" `g` by the scalar `a` (i.e., adding `g` to itself `a` times in elliptic-curve terminology) |
| `A * B` | Group operation: point addition of elements `A` and `B` in G |
| `1` | The identity element of G (the point at infinity / zero point) |

**Notation convention:** We write `g^a` using exponential notation rather than the additive `a * g` or `[a]G` because it makes the ElGamal formulas and the homomorphic property much clearer. In implementation, every `g^a` is a single scalar-multiplication call.

**Important identities:**
- `g^0 = 1` (the identity element)
- `g^a * g^b = g^(a+b)` (the group operation corresponds to scalar addition in the exponent)
- `(g^a)^b = g^(a*b)` (repeated scalar multiplication)

---

## 2. Key Generation

### 2.1 Single-trustee key (conceptual)

A single key pair consists of:

- **Private key:** `x` sampled uniformly at random from `Z_q`
- **Public key:** `h = g^x`

Given `h`, recovering `x` requires solving the discrete logarithm problem in G, which is infeasible (~2^126 group operations via Pollard's rho).

### 2.2 Threshold key generation (Feldman VSS)

In otvoren-vot, no single entity holds the full private key. Instead, 9 trustees collectively generate a shared key using Feldman's Verifiable Secret Sharing with a 5-of-9 threshold.

**Setup phase** (executed once, weeks before election day):

1. Each trustee `j` (for `j = 1, ..., 9`) generates a random polynomial of degree `t-1 = 4`:

   ```
   f_j(z) = a_{j,0} + a_{j,1}*z + a_{j,2}*z^2 + a_{j,3}*z^3 + a_{j,4}*z^4   (mod q)
   ```

   where each coefficient `a_{j,k}` is sampled uniformly from `Z_q` inside the trustee's HSM.

2. Each trustee publishes **commitments** to their polynomial coefficients:

   ```
   C_{j,k} = g^{a_{j,k}}   for k = 0, 1, 2, 3, 4
   ```

   These commitments are broadcast to all other trustees and recorded on the bulletin board.

3. Each trustee `j` privately sends the evaluation `f_j(i)` to trustee `i` (for every `i != j`), over an authenticated encrypted channel (HSM-to-HSM, or TLS-secured).

4. Each trustee `i` **verifies** the received share from trustee `j` using the published commitments:

   ```
   g^{f_j(i)} =? C_{j,0} * C_{j,1}^i * C_{j,2}^{i^2} * C_{j,3}^{i^3} * C_{j,4}^{i^4}
   ```

   If the check fails, trustee `i` broadcasts a complaint. The protocol resolves complaints by having the accused trustee reveal the share publicly (at which point it is verified by everyone). Malicious trustees are excluded and the protocol restarts with the remaining set if needed.

5. Each trustee `i` computes their **combined secret share**:

   ```
   x_i = f_1(i) + f_2(i) + ... + f_9(i)   (mod q)
   ```

   This share `x_i` never leaves the HSM. The full private key `x = x_1 + x_2 + ... + x_9` is never computed or assembled anywhere — it exists only implicitly as the sum of shares evaluated at each trustee's index.

   More precisely, the combined polynomial is `F(z) = f_1(z) + f_2(z) + ... + f_9(z)`, and `x = F(0)`, while `x_i = F(i)`. The key `x` can be reconstructed from any 5 shares via Lagrange interpolation, but this reconstruction never happens — instead, partial decryptions are combined (see Section 7).

6. The **election public key** is computed by all parties:

   ```
   h = C_{1,0} * C_{2,0} * ... * C_{9,0} = g^{a_{1,0}} * g^{a_{2,0}} * ... * g^{a_{9,0}} = g^x
   ```

   where `x = a_{1,0} + a_{2,0} + ... + a_{9,0}` (the sum of the constant terms).

7. Each trustee publishes their **verification key**:

   ```
   h_i = g^{x_i}
   ```

   This allows anyone to verify the trustee's partial decryption during the ceremony (see Section 7).

**Result:** A public key `h` for encryption, and 9 secret shares `x_1, ..., x_9` distributed across 9 HSMs. Any 5 shares suffice to decrypt; fewer than 5 reveal no information about the private key (information-theoretic secrecy of Shamir's scheme).

---

## 3. Encryption

Given a plaintext bit `m` (where `m` is 0 or 1) and the election public key `h`:

1. Sample a fresh random scalar `r` uniformly from `Z_q`
2. Compute the ciphertext `(c1, c2)`:

```
c1 = g^r
c2 = h^r * g^m
```

The ciphertext is a pair of group elements: `(c1, c2) = (g^r, h^r * g^m)`.

**Why "exponential" ElGamal:** In standard (textbook) ElGamal, the message `m` is a group element and the ciphertext is `(g^r, h^r * m)`. Here, the message is an *integer* placed in the exponent: `g^m`. This means decryption recovers `g^m` rather than `m` directly — recovering `m` from `g^m` requires solving a (small) discrete logarithm. The trade-off is worth it because exponential ElGamal gains **additive homomorphism**: multiplying ciphertexts adds the messages in the exponent (see Section 4).

**Ciphertext size:** Each element of G is 32 bytes (Ristretto255 canonical encoding), so one ciphertext is 64 bytes.

**Randomness is critical:** Each encryption MUST use a fresh, independent `r` sampled from a cryptographically secure random number generator. Reusing `r` across two encryptions leaks the difference of the plaintexts. In the browser, `r` is generated via `crypto.getRandomValues()` fed into libsodium's `crypto_core_ristretto255_scalar_random()`.

---

## 4. Homomorphic Property

The key feature enabling vote tallying without decryption.

Given two ciphertexts encrypting messages `a` and `b`:

```
Enc(a, r1) = (g^{r1},  h^{r1} * g^a)
Enc(b, r2) = (g^{r2},  h^{r2} * g^b)
```

Their element-wise product is:

```
Enc(a, r1) * Enc(b, r2) = (g^{r1} * g^{r2},  h^{r1} * g^a * h^{r2} * g^b)
                         = (g^{r1 + r2},  h^{r1 + r2} * g^{a + b})
                         = Enc(a + b,  r1 + r2)
```

**The product of two ciphertexts is a valid encryption of the sum of the plaintexts**, under the combined randomness `r1 + r2`.

This extends to any number of ciphertexts. For `N` voters each encrypting `m_i` with randomness `r_i`:

```
product_{i=1}^{N} Enc(m_i, r_i) = Enc(sum_{i=1}^{N} m_i,  sum_{i=1}^{N} r_i)
```

The server computes this product using only the public ciphertexts — it never needs private keys, never sees individual votes, and the result is a valid ciphertext of the total vote count for that slot.

---

## 5. Ballot Encoding

Each voter's ballot is a structured collection of binary vectors, each element encrypted independently.

### 5.1 Party vector

A one-hot vector of length `P` (where `P` is the number of parties, up to 50):

```
party_vector = [0, 0, ..., 1, ..., 0]
                            ^
                         party i selected
```

Exactly one position is 1; all others are 0. Each element is encrypted independently:

```
E_party = [Enc(0), Enc(0), ..., Enc(1), ..., Enc(0)]
```

The ZK ballot validity proof (Sigma protocol) ensures:
- Each element encrypts either 0 or 1 (OR-proof)
- The elements sum to exactly 1 (sum-proof using the homomorphic property)

### 5.2 Candidate vectors

For each party `j`, a vector of length `C_j` (where `C_j` is the number of candidates for party `j`, up to 50):

```
candidates_j = [0, 0, ..., 1, ..., 0]   if voter selected a candidate from party j
candidates_j = [0, 0, ..., 0, ..., 0]   if party j is not the voter's chosen party
                                          OR if voter made no candidate preference
```

Each element encrypted independently. The ZK validity proof ensures:
- Each element encrypts 0 or 1
- Each candidate vector sums to 0 or 1
- Only the selected party's candidate vector may sum to 1; all others sum to 0

### 5.3 Total encrypted elements

In the worst case (50 parties, each with 50 candidates):

| Component | Count |
|-----------|-------|
| Party vector | 50 elements |
| Candidate vectors | 50 parties x 50 candidates = 2,500 elements |
| **Total** | **2,550 encrypted elements** |

Each element is a 64-byte ciphertext, so the total ballot ciphertext is `2,550 * 64 = 163,200 bytes` (~160 KB), before proofs.

### 5.4 Why encrypt zeros

Every candidate vector for every party is encrypted, even if the voter did not select that party (all zeros). This is essential: if unselected parties' vectors were omitted or left unencrypted, an observer could determine the voter's party choice from the ballot's structure. Encrypting everything makes all ballots the same size and structure, revealing nothing about the vote.

---

## 6. Homomorphic Tallying

After the active ballot set is determined (via the deduplication process), the Tally Service computes the element-wise product across all `N` active ballots.

For the party vector:

```
tally_party[k] = product_{i=1}^{N} E_party_i[k]    for k = 1, ..., P
```

By the homomorphic property (Section 4), `tally_party[k]` encrypts `sum_{i=1}^{N} m_{i,k}` — the total number of votes for party `k`.

Similarly, for each party `j`'s candidate vector:

```
tally_candidates_j[k] = product_{i=1}^{N} E_candidates_{i,j}[k]    for k = 1, ..., C_j
```

This encrypts the total preference votes for candidate `k` of party `j`.

**Computation cost:** Each element-wise multiplication is a pair of Ristretto255 point additions (one for `c1`, one for `c2`). For 4 million ballots and 2,550 slots:

```
Total point additions = 4,000,000 * 2,550 * 2 = 20,400,000,000
```

At ~100 nanoseconds per point addition on modern hardware, this takes approximately:

```
20.4 * 10^9 * 100 * 10^-9 seconds = ~2,040 seconds = ~34 minutes
```

This is parallelizable across slots (2,550 independent aggregations) and across batches within each slot. On a 64-core server, wall-clock time is approximately:

```
34 minutes / 64 cores ~ 32 seconds (slot-parallel)
```

In practice, with memory bandwidth considerations, expect ~1-5 minutes on production hardware.

---

## 7. Threshold Decryption

After homomorphic tallying produces encrypted sums, 5 or more of the 9 trustees decrypt them without reconstructing the private key.

### 7.1 Partial decryption

For a single tally ciphertext `(c1, c2)` encrypting the total `m`:

```
c1 = g^R      (where R = sum of all randomness)
c2 = h^R * g^m
```

Trustee `i` computes their **partial decryption** using their secret share `x_i`:

```
d_i = c1^{x_i} = g^{R * x_i}
```

This computation happens entirely inside the trustee's HSM — the share `x_i` never leaves the device. The HSM outputs `d_i` along with a Chaum-Pedersen proof (see Section 7.2).

### 7.2 Chaum-Pedersen proof of correct partial decryption

Each trustee proves that `d_i = c1^{x_i}` using the same `x_i` that satisfies `h_i = g^{x_i}`. This is a proof of discrete-log equality: "the exponent relating `d_i` to `c1` is the same as the exponent relating `h_i` to `g`."

The Chaum-Pedersen protocol (non-interactive via Fiat-Shamir):

1. **Commit:** The HSM samples `k` uniformly from `Z_q` and computes:
   ```
   a1 = g^k
   a2 = c1^k
   ```

2. **Challenge:** Compute the challenge hash:
   ```
   e = Hash(g, h_i, c1, d_i, a1, a2)
   ```
   using SHA-256 or BLAKE2b, interpreted as a scalar in `Z_q`.

3. **Response:** Compute:
   ```
   s = k - e * x_i   (mod q)
   ```

4. **Proof:** The tuple `(a1, a2, s)` is published alongside `d_i`.

**Verification** (by anyone): Given `(g, h_i, c1, d_i, a1, a2, s)`:

1. Recompute: `e = Hash(g, h_i, c1, d_i, a1, a2)`
2. Check: `g^s * h_i^e == a1`
3. Check: `c1^s * d_i^e == a2`

If both checks pass, the verifier is convinced that the person who produced `d_i` knows `x_i` such that `d_i = c1^{x_i}` and `h_i = g^{x_i}`.

### 7.3 Combining partial decryptions

Let `S` be the set of contributing trustees (|S| >= 5). The Lagrange interpolation coefficients for trustee `i` in set `S` are:

```
lambda_i = product_{j in S, j != i}  (j / (j - i))   (mod q)
```

where `i` and `j` are the trustee indices (1 through 9).

The combined decryption factor is:

```
D = product_{i in S} d_i^{lambda_i}
  = product_{i in S} (c1^{x_i})^{lambda_i}
  = c1^{sum_{i in S} x_i * lambda_i}
  = c1^x
  = g^{R*x}
  = h^R
```

The last equality holds because Lagrange interpolation recovers the secret: `sum_{i in S} x_i * lambda_i = x`.

### 7.4 Recovering `g^m`

With the combined decryption factor `D = h^R`:

```
g^m = c2 / D = (h^R * g^m) / h^R = g^m
```

More precisely, we compute `c2 * D^{-1}` (multiply `c2` by the inverse of `D` in the group), which yields `g^m`.

At this point we have the group element `g^m` but need the integer `m`. Since `m` is a vote count, it is bounded by the number of voters — see Section 8.

---

## 8. Discrete Log Recovery (Baby-Step Giant-Step)

After threshold decryption, we have `g^m` and need to recover `m`, where `m` is the total number of votes for a particular option. We know `0 <= m <= N` where `N` is the total number of voters (at most ~4 million for Bulgarian national elections).

### 8.1 The BSGS algorithm

Baby-step giant-step finds `m` in `O(sqrt(N))` time and space:

1. **Choose step size:** `s = ceil(sqrt(N))`. For `N = 4,000,000`: `s = 2,000`.

2. **Baby steps:** Precompute and store a lookup table:
   ```
   table = {}
   for j = 0 to s-1:
       table[g^j] = j
   ```
   This requires `s` scalar multiplications and `s` table entries.

3. **Giant steps:** Compute `g^{-s}` (the inverse of `g^s` in the group). Then:
   ```
   gamma = g^m   (the value to solve)
   for i = 0 to s-1:
       if gamma in table:
           return m = i*s + table[gamma]
       gamma = gamma * g^{-s}
   ```

4. **Result:** `m = i*s + j` where `i` is the giant-step index and `j` is the baby-step index found in the table.

### 8.2 Performance

| Parameter | Value |
|-----------|-------|
| Max voters `N` | 4,000,000 |
| Step size `s` | 2,000 |
| Baby steps (precompute) | 2,000 scalar multiplications |
| Giant steps per slot (worst case) | 2,000 scalar multiplications + 2,000 table lookups |
| Total tally slots | 2,550 (50 parties + 50 x 50 candidates) |

The baby-step table is **shared** across all 2,550 slots (computed once). The giant-step phase runs independently per slot.

**Time estimate:**
- Baby-step table: 2,000 scalar multiplications ~ 0.24 ms
- Giant steps per slot: up to 2,000 scalar multiplications ~ 0.24 ms
- All 2,550 slots: 2,550 * 0.24 ms ~ 612 ms

**Total: well under 1 second** on modern hardware (single-threaded). With parallelism across slots, this is essentially instant.

### 8.3 Why this works

BSGS is feasible here only because `m` is small (bounded by the number of voters). If `m` could be an arbitrary 252-bit scalar, BSGS would require `O(2^126)` steps — computationally infeasible. The ballot encoding ensures every vote is 0 or 1 (proven by the Sigma proof), so the sum is at most `N`.

---

## 9. Performance Budget

### 9.1 Client-side (voter's browser)

All encryption and proof generation happens in the voter's browser using libsodium.js (WASM).

| Operation | Count | Cost per op | Total |
|-----------|-------|------------|-------|
| ElGamal encryption (2 scalar muls) | 2,550 | ~0.3 ms | ~765 ms |
| Sigma OR-proof per element (4 scalar muls) | 2,550 | ~0.6 ms | ~1,530 ms |
| Sum proofs (party + candidate vectors) | 51 proofs | ~1 ms | ~51 ms |
| Random scalar generation | 2,550 | ~0.01 ms | ~26 ms |
| Serialization + hashing | — | — | ~100 ms |
| **Total (estimated)** | | | **~2.5 seconds** |

**Target:** Under 5 seconds on a mid-range 2024 laptop. The estimates above suggest ~2.5 seconds, leaving headroom for slower devices and browser overhead. If client-side proof generation exceeds 5 seconds on benchmark devices, we use batched Sigma proofs (amortized multi-statement proofs) to reduce the per-element cost.

**Benchmark devices for the 5-second target:**
- Laptop: Intel i5-1235U or AMD Ryzen 5 7530U (2024 mid-range)
- Tablet: Apple M1 iPad or equivalent ARM
- Phone: not a primary target (voters use laptops for eAuth), but should degrade gracefully

### 9.2 Server-side (Tally Service)

| Operation | Estimate |
|-----------|----------|
| Homomorphic tallying (4M ballots, 2,550 slots) | 1-5 minutes (64 cores) |
| BSGS discrete log recovery (2,550 slots) | < 1 second |
| Deduplication SNARK proving (4M ballots) | 30-60 minutes (64 cores, recursive batching) |
| Sigma proof verification (all ballots) | Batch-verifiable; minutes for 4M ballots |

### 9.3 Bandwidth

| Data | Size |
|------|------|
| Single ballot ciphertext (2,550 elements x 64 bytes) | ~160 KB |
| Sigma proofs per ballot | ~200 KB (estimated) |
| Total upload per voter | ~360 KB |
| Total bulletin board (4M voters) | ~1.4 TB |

The bulletin board is append-only and write-heavy during the election, read-heavy afterward for verification.

---

## 10. Implementation Notes

### 10.1 Go (server-side)

**Library:** `filippo.io/edwards25519`

This package provides constant-time Ristretto255 operations. Key types and functions:

```go
import "filippo.io/edwards25519"

// Scalars (elements of Z_q)
var x edwards25519.Scalar          // private key / randomness
x.SetUniformBytes(randomBytes[:])  // sample from 64 uniform bytes

// Points (elements of G)
var g edwards25519.Point
g.Set(edwards25519.NewGeneratorPoint())  // the basepoint

var h edwards25519.Point
h.ScalarMult(&x, &g)              // h = g^x

// ElGamal encryption
var r edwards25519.Scalar
r.SetUniformBytes(randomBytes[:])

var c1, c2 edwards25519.Point
c1.ScalarMult(&r, &g)             // c1 = g^r

var hr edwards25519.Point
hr.ScalarMult(&r, &h)             // h^r

var gm edwards25519.Point
gm.ScalarMult(&m, &g)             // g^m  (m is 0 or 1)

c2.Add(&hr, &gm)                  // c2 = h^r * g^m

// Homomorphic addition (tallying)
var sum1, sum2 edwards25519.Point
sum1.Add(&ballot1_c1, &ballot2_c1)
sum2.Add(&ballot1_c2, &ballot2_c2)
```

**Important:** `SetUniformBytes` takes 64 bytes (512 bits) and reduces modulo `q` to produce a uniformly distributed scalar. Do NOT use `SetCanonicalBytes` (32 bytes) for random scalar generation — it does not produce a uniform distribution over `Z_q`.

### 10.2 Browser (client-side)

**Library:** `libsodium.js` (libsodium compiled to WASM), using the low-level Ristretto255 API.

libsodium does NOT provide ElGamal as a built-in. We implement it as custom code using the following primitives:

```javascript
// Available libsodium.js Ristretto255 primitives:
sodium.crypto_core_ristretto255_random()           // random point
sodium.crypto_core_ristretto255_scalar_random()    // random scalar in Z_q
sodium.crypto_core_ristretto255_from_hash(hash64)  // hash-to-point
sodium.crypto_scalarmult_ristretto255(scalar, point)    // scalar * point = point^scalar
sodium.crypto_core_ristretto255_add(point_a, point_b)  // point addition
sodium.crypto_core_ristretto255_sub(point_a, point_b)  // point subtraction
sodium.crypto_core_ristretto255_scalar_add(a, b)       // scalar addition mod q
sodium.crypto_core_ristretto255_scalar_sub(a, b)       // scalar subtraction mod q
sodium.crypto_core_ristretto255_scalar_negate(a)       // -a mod q
sodium.crypto_core_ristretto255_scalar_invert(a)       // a^{-1} mod q
sodium.crypto_scalarmult_ristretto255_base(scalar)     // scalar * basepoint (faster)
```

**ElGamal encryption in the browser:**

```javascript
function encrypt(message_bit, election_pubkey_h) {
    // message_bit is 0 or 1 (as a Uint8Array scalar: 0x00...00 or 0x01...00)
    const r = sodium.crypto_core_ristretto255_scalar_random();

    // c1 = g^r (basepoint multiplication — optimized path)
    const c1 = sodium.crypto_scalarmult_ristretto255_base(r);

    // c2 = h^r * g^m
    const h_r = sodium.crypto_scalarmult_ristretto255(r, election_pubkey_h);
    const g_m = sodium.crypto_scalarmult_ristretto255_base(message_bit);
    const c2 = sodium.crypto_core_ristretto255_add(h_r, g_m);

    return { c1, c2, r };  // r is kept for the ZK proof, then discarded
}
```

**Security requirements for the browser implementation:**
- The randomness `r` for each encryption MUST be generated independently via `crypto_core_ristretto255_scalar_random()` (which uses `crypto.getRandomValues()` internally)
- After the Sigma proof is computed, `r` MUST be zeroed from memory (`sodium.memzero(r)`)
- The libsodium WASM binary is bundled with the web app and its SHA-256 hash is published on the bulletin board for integrity verification
- The browser extension independently verifies the hash of the served JavaScript before the voter interacts with it

### 10.3 Interoperability

The Go server and JavaScript client operate on the same group (Ristretto255) and must produce compatible encodings:

- Points are serialized as 32-byte canonical Ristretto255 encodings
- Scalars are serialized as 32-byte little-endian integers reduced modulo `q`
- Ciphertexts are serialized as `c1 || c2` (64 bytes, no length prefix within the pair)
- Both `filippo.io/edwards25519` and `libsodium` use identical Ristretto255 encodings (RFC 8032 + Ristretto construction)

**Test vectors:** A set of known-answer test vectors (plaintext, randomness, expected ciphertext) is maintained in `crypto/testdata/` and cross-validated between the Go and JavaScript implementations during CI.
