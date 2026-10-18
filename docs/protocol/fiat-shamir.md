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
| Go (`github.com/gtank/ristretto255`) | `ristretto255.NewScalar().SetUniformBytes(digest)` (64-byte SHA-512 digest) |
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

`lp(x)` below abbreviates `len_prefix(x)`, and `u32be(n)` is the 4-byte
big-endian encoding of the integer `n`. A `u32be` field is therefore written as
`lp(u32be(n))`: a 4-byte length prefix (`00 00 00 04`) followed by 4 bytes.

### Field Encoding

- **Domain separator:** Raw ASCII bytes (no null terminator). E.g., the string
  `"otvoren-vot.ballot-binary-proof"` is 31 bytes.
- **Points:** 32-byte canonical Ristretto255 compressed encoding (little-endian
  per the Ristretto255 spec).
- **Scalars:** 32-byte little-endian encoding of the integer modulo `q`.
- **Identifiers (`election_id`, `ballot_id`):** their wire strings as UTF-8
  bytes, exactly as transmitted, with no normalisation (no Unicode
  normalisation, trimming or case folding). An empty identifier is invalid and
  must be rejected before any transcript is built.
- **Indices (`index`, `trustee_index`, `slot_index`):** `u32be(n)`, carried as
  `lp(u32be(n))`.
- **Digests and commitments (`tally_digest`, `set_commitment`, `sealed_head`):**
  raw 32-byte SHA-256 outputs.

### Ballot-Proof Context

Every ballot-proof transcript (binary, sum, candidate-sum, consistency) begins
with the same context, directly after the domain separator and before any
existing field:

```
lp(domain) || lp(utf8(election_id)) || lp(utf8(ballot_id)) || lp(u32be(index)) || ...existing fields
```

`index` is the statement index defined in `ballot-proofs.md` section 8.4. The
context binds each proof to one election, one ballot and one position within
that ballot, so a proof cannot be replayed into another election, another
ballot or another slot. Nothing that was previously in a transcript is removed;
the context fields are inserted immediately after the domain.

### Concrete Example

For the binary proof Fiat-Shamir challenge:

```
hash_input =
  uint32_be(31) || "otvoren-vot.ballot-binary-proof"   // domain
  uint32_be(49) || utf8(election_id)                     // election_id (49 bytes in this example)
  uint32_be(36) || utf8(ballot_id)                       // ballot_id (36 bytes in this example)
  uint32_be(4)  || u32be(index)                          // statement index (4 bytes)
  uint32_be(32) || public_key_bytes                      // public key (32 bytes)
  uint32_be(32) || C1_bytes                              // ciphertext C1 (32 bytes)
  uint32_be(32) || C2_bytes                              // ciphertext C2 (32 bytes)
  uint32_be(32) || A0_bytes                              // commitment A0 (32 bytes)
  uint32_be(32) || B0_bytes                              // commitment B0 (32 bytes)
  uint32_be(32) || A1_bytes                              // commitment A1 (32 bytes)
  uint32_be(32) || B1_bytes                              // commitment B1 (32 bytes)
```

In this example `election_id` is `избори-2027-народно-събрание`, which is 49
UTF-8 bytes (Cyrillic letters take 2 bytes each), and `ballot_id` is a 36-character
UUID string such as `0b8c1f5e-4a7d-4e2a-9c3b-6d1f2a8e7c40` (36 bytes). The
identifier lengths are variable; only the structure is normative.

Total: domain (4 + 31 = 35) + election_id (4 + 49 = 53) + ballot_id
(4 + 36 = 40) + index (4 + 4 = 8) + 7 x (4 + 32) = 252 =
35 + 53 + 40 + 8 + 252 = 388 bytes input to SHA-512.

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
FiatShamir(domain, election_id, ballot_id, index, public_key, C1, C2, A0, B0, A1, B1) -> challenge e
```

The statement part is `(pk, C1, C2, A0, B0, A1, B1)`, preceded by the
ballot-proof context.

Where `(C1, C2)` is the ciphertext being proven and `(A0, B0, A1, B1)` are the
commitment points for branches 0 and 1.

**Critical:** The public key is included in the transcript to bind the proof to
the election key and prevent key-substitution attacks.

### Sum-Equals-One Proof (Standard Chaum-Pedersen)

```
FiatShamir(domain, election_id, ballot_id, index, public_key, C1_agg, C2_agg, A, B) -> challenge e
```

The statement part is `(pk, C1_agg, C2_agg, A, B)`, preceded by the
ballot-proof context.

Where `(C1_agg, C2_agg)` is the homomorphic sum of all party ciphertexts
and `(A, B)` is the commitment pair.

### Candidate Sum Proof

Same structure (including the ballot-proof context and the fields
`pk, C1, C2, A0, B0, A1, B1`) as the binary proof, applied to the homomorphic
aggregate of a party's candidate vector. Uses its own domain separator.

### Consistency Proof

Same structure (including the ballot-proof context and the fields
`pk, C1, C2, A0, B0, A1, B1`) as the binary proof, applied to the homomorphic difference ciphertext
`(party_ct - cand_sum_ct)`. Uses its own domain separator. The verifier
recomputes the difference ciphertext independently.

### Partial-Decryption Proof (Chaum-Pedersen)

Domain: `otvoren-vot.chaum-pedersen`. Fields, in order, each `lp`-framed:

1. `lp(domain)`
2. `lp(utf8(election_id))`
3. `lp(u32be(trustee_index))`
4. `lp(u32be(slot_index))`
5. `lp(c2)` the 32-byte `c2` of the ciphertext in the tally slot being decrypted
6. `lp(tally_digest)` (32 bytes)
7. `lp(set_commitment)` (32 bytes)
8. `lp(sealed_head)` (32 bytes)
9. the statement and commitments: `lp(G)`, `lp(c1)`, `lp(h_i)`, `lp(d_i)`,
   `lp(u)`, `lp(v)`

That is the domain plus seven context fields, followed by the six statement
and commitment points. It is the generic Chaum-Pedersen transcript
`g, h, A, B, u, v` with `g = G`, `h = c1`, `A = h_i` (the trustee's public
verification key share) and `B = d_i` (the partial decryption `x_i * c1`),
and `(u, v)` the commitments `(k*G, k*c1)`.

The response is `z = k + e*x_i`. A verifier accepts iff both
`z*G = u + e*h_i` and `z*c1 = v + e*d_i` hold.

Context definitions:

- `tally_digest = SHA-256(lp("otvoren-vot.tally-vector") || lp(c1_0 || c2_0) || ... || lp(c1_{n-1} || c2_{n-1}))`,
  computed over the published tally vector in canonical slot order (the order
  of `ballot-proofs.md` section 8.4); each entry `c1_j || c2_j` is 64 bytes.
  The domain `otvoren-vot.tally-vector` is 24 bytes.
- `set_commitment` is Collection's salted commitment to the active set of
  accepted ballots that produced the tally.
- `sealed_head` is the SHA-256 of the bulletin board's sealed signed head at
  the time the tally was fixed.

These bind a partial decryption to one election, one trustee, one slot, one
exact tally vector, one ballot set and one board state. See the core-voting-loop
design (section 5.2.4) for how `set_commitment` and `sealed_head` are produced
and published.

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
   vectors in `crypto/vectors/testdata/vectors.json`.

## Reference Implementation

- **Go:** `crypto/internal/scalar.go` function `FiatShamir`
- **TypeScript:** `web/src/crypto/fiatShamir.ts`
- **Test vectors:** `crypto/vectors/testdata/vectors.json`
