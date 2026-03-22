# Fiat-Shamir Transcript Format

All Sigma proofs in otvoren-vot use the following Fiat-Shamir transform to make
interactive proofs non-interactive. This document specifies the exact byte-level
format so that independent implementations (Go server, TypeScript browser client)
produce identical challenges for the same inputs.

## Hash Function

SHA-512, with the 64-byte digest reduced to a Ristretto255 scalar via
`SetUniformBytes` (little-endian 512-bit integer reduced modulo the group order
`q = 2^252 + 27742317777372353535851937790883648493`).

| Library | Function |
|---------|----------|
| Go (`filippo.io/edwards25519`) | `edwards25519.NewScalar().SetUniformBytes(digest[:64])` |
| TypeScript (libsodium WASM) | `crypto_core_ristretto255_scalar_reduce(sha512(input))` |

## Transcript Format

```
hash_input = len_prefix(domain) || len_prefix(data[0]) || len_prefix(data[1]) || ...
```

where `len_prefix(x)` is:

```
uint32_be(len(x)) || x
```

Each field is prefixed with a **4-byte big-endian unsigned 32-bit integer** encoding
its byte length. This prevents ambiguity when fields have variable sizes.

### Field Encoding

- **Domain separator:** Raw ASCII bytes (no null terminator). E.g., the string
  `"otvoren-vot.ballot-binary-proof"` is 31 bytes.
- **Points:** 32-byte canonical Ristretto255 compressed encoding (little-endian
  per the Ristretto255 spec).
- **Scalars:** 32-byte little-endian encoding of the integer modulo `q`.

### Concrete Example

For the binary proof Fiat-Shamir challenge:

```
hash_input =
  uint32_be(31) || "otvoren-vot.ballot-binary-proof"   // domain
  uint32_be(32) || public_key_bytes                      // public key (32 bytes)
  uint32_be(32) || C1_bytes                              // ciphertext C1 (32 bytes)
  uint32_be(32) || C2_bytes                              // ciphertext C2 (32 bytes)
  uint32_be(32) || A0_bytes                              // commitment A0 (32 bytes)
  uint32_be(32) || B0_bytes                              // commitment B0 (32 bytes)
  uint32_be(32) || A1_bytes                              // commitment A1 (32 bytes)
  uint32_be(32) || B1_bytes                              // commitment B1 (32 bytes)
```

Total: 4 + 31 + 7*(4 + 32) = 4 + 31 + 252 = 287 bytes input to SHA-512.

## Domain Separators

Each proof type uses a unique domain separator string to prevent cross-protocol
attacks (a valid proof for one statement cannot be replayed as a proof for a
different statement type).

| Proof | Domain Separator |
|-------|-----------------|
| Party binary (m in {0,1}) | `otvoren-vot.ballot-binary-proof` |
| Party vector sum = 1 | `otvoren-vot.ballot-sum-proof` |
| Candidate sum in {0,1} per party | `otvoren-vot.candidate-sum-01-proof` |
| Conditional consistency (party - cand_sum in {0,1}) | `otvoren-vot.candidate-consistency-proof` |
| Chaum-Pedersen (discrete log equality) | `otvoren-vot.chaum-pedersen` |

## Transcript Contents per Proof Type

### Binary Proof (Disjunctive Chaum-Pedersen)

```
FiatShamir(domain, public_key, C1, C2, A0, B0, A1, B1) -> challenge e
```

Where `(C1, C2)` is the ciphertext being proven and `(A0, B0, A1, B1)` are the
commitment points for branches 0 and 1.

**Critical:** The public key is included in the transcript to bind the proof to
the election key and prevent key-substitution attacks.

### Sum-Equals-One Proof (Standard Chaum-Pedersen)

```
FiatShamir(domain, public_key, C1_agg, C2_agg, A, B) -> challenge e
```

Where `(C1_agg, C2_agg)` is the homomorphic sum of all party ciphertexts
and `(A, B)` is the commitment pair.

### Candidate Sum Proof

Same structure as binary proof, applied to the homomorphic aggregate of a party's
candidate vector. Uses its own domain separator.

### Consistency Proof

Same structure as binary proof, applied to the homomorphic difference ciphertext
`(party_ct - cand_sum_ct)`. Uses its own domain separator. The verifier
recomputes the difference ciphertext independently.

## Security Properties

1. **Domain separation:** Different domain strings produce different hash
   outputs even for identical data, preventing cross-protocol forgery.

2. **Completeness of transcript:** All public inputs (public key, ciphertext,
   commitments) are included. Omitting any element would allow proof malleability.

3. **Length-prefix framing:** Prevents concatenation ambiguity. Without length
   prefixes, `data = ["ab", "cd"]` and `data = ["abcd"]` would produce the same
   hash input.

4. **Deterministic:** Given identical inputs, Go and TypeScript implementations
   produce the same challenge scalar. This is verified by the cross-language test
   vectors in `crypto/testdata/vectors.json`.

## Reference Implementation

- **Go:** `crypto/internal/scalar.go` function `FiatShamir`
- **TypeScript:** `web/src/crypto/fiat-shamir.ts` (to be implemented)
- **Test vectors:** `crypto/testdata/vectors.json`
