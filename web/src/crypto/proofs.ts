import { getSodium } from './sodium'
import { fiatShamir } from './fiatShamir'
import { type Ciphertext, homomorphicSum } from './elgamal'

// Domain separators of docs/protocol/fiat-shamir.md; identical to the Go
// constants in crypto/proof/{binary,sum,candidate}.go.
const BINARY_DOMAIN = 'otvoren-vot.ballot-binary-proof'
const SUM_DOMAIN = 'otvoren-vot.ballot-sum-proof'
const CANDIDATE_SUM_DOMAIN = 'otvoren-vot.candidate-sum-01-proof'
const CONSISTENCY_DOMAIN = 'otvoren-vot.candidate-consistency-proof'

const MAX_UINT32 = 0xffffffff

// ---------------------------------------------------------------------------
// Ballot-proof context
// ---------------------------------------------------------------------------

/**
 * Binds a ballot proof to one election, one ballot and one position within
 * that ballot (docs/protocol/fiat-shamir.md, "Ballot-Proof Context"). `index`
 * is the statement index of docs/protocol/ballot-proofs.md section 8.4, a
 * uint32. Mirrors Go's proof.Context.
 */
export interface ProofContext {
  electionId: string
  ballotId: string
  index: number
}

/** Why ctx cannot be used, or null when it can. */
function contextProblem(ctx: ProofContext): string | null {
  if (typeof ctx.electionId !== 'string' || ctx.electionId.length === 0) return 'empty election id'
  if (typeof ctx.ballotId !== 'string' || ctx.ballotId.length === 0) return 'empty ballot id'
  if (!Number.isInteger(ctx.index) || ctx.index < 0 || ctx.index > MAX_UINT32) {
    return `index ${String(ctx.index)} is not a uint32`
  }
  return null
}

/**
 * The context fields in transcript order: utf8(election_id), utf8(ballot_id),
 * u32be(index). fiatShamir length-prefixes each one. Mirrors the first three
 * fields of Go's ballotChallenge (crypto/proof/context.go).
 */
function encodeContext(ctx: ProofContext): Uint8Array[] {
  const index = new Uint8Array(4)
  new DataView(index.buffer).setUint32(0, ctx.index, false)
  const utf8 = new TextEncoder()
  return [utf8.encode(ctx.electionId), utf8.encode(ctx.ballotId), index]
}

/** Prover side: the encoded context, or a thrown error for an unusable one. */
function requireContext(ctx: ProofContext): Uint8Array[] {
  const problem = contextProblem(ctx)
  if (problem !== null) throw new Error(`Invalid proof context: ${problem}`)
  return encodeContext(ctx)
}

/**
 * Prover side: throws unless `pubKey` is a wire point. Go's provers refuse a
 * nil or identity key with ErrMalformed; the provers' scalar-mults are
 * identity-tolerant, so the refusal has to be explicit here.
 */
function requirePublicKey(domain: string, pubKey: Uint8Array): void {
  if (!isPoint(pubKey)) throw new Error(`${domain}: public key is not a valid non-identity point`)
}

/** Verifier side: the encoded context, or null for an unusable one. */
function contextOrNull(ctx: ProofContext): Uint8Array[] | null {
  return contextProblem(ctx) === null ? encodeContext(ctx) : null
}

// ---------------------------------------------------------------------------
// Transcripts (docs/protocol/fiat-shamir.md, "Transcript Contents")
// ---------------------------------------------------------------------------

/**
 * Binary, candidate-sum and consistency proofs:
 * FiatShamir(domain, election_id, ballot_id, index, pk, C1, C2, A0, B0, A1, B1).
 * Mirrors Go's binaryChallenge (crypto/proof/binary.go).
 */
function binaryChallenge(
  domain: string,
  context: Uint8Array[],
  pubKey: Uint8Array,
  ct: Ciphertext,
  a0: Uint8Array,
  b0: Uint8Array,
  a1: Uint8Array,
  b1: Uint8Array,
): Uint8Array {
  return fiatShamir(domain, ...context, pubKey, ct.c1, ct.c2, a0, b0, a1, b1)
}

/**
 * Sum-equals-one proof:
 * FiatShamir(domain, election_id, ballot_id, index, pk, C1_agg, C2_agg, A, B).
 * Mirrors Go's sumChallenge (crypto/proof/sum.go).
 */
function sumChallenge(
  context: Uint8Array[],
  pubKey: Uint8Array,
  aggCt: Ciphertext,
  a: Uint8Array,
  b: Uint8Array,
): Uint8Array {
  return fiatShamir(SUM_DOMAIN, ...context, pubKey, aggCt.c1, aggCt.c2, a, b)
}

// ---------------------------------------------------------------------------
// Binary proof (disjunctive Chaum-Pedersen)
// ---------------------------------------------------------------------------

export interface BinaryProof {
  a0: Uint8Array  // 32 bytes — commitment for branch 0
  b0: Uint8Array  // 32 bytes
  a1: Uint8Array  // 32 bytes — commitment for branch 1
  b1: Uint8Array  // 32 bytes
  e0: Uint8Array  // 32 bytes — challenge for branch 0
  e1: Uint8Array  // 32 bytes — challenge for branch 1
  z0: Uint8Array  // 32 bytes — response for branch 0
  z1: Uint8Array  // 32 bytes — response for branch 1
}

/**
 * Proves, bound to `ctx`, that `ct` encrypts 0 or 1 using a disjunctive
 * Chaum-Pedersen proof. Throws on an empty ID or an index that is not a uint32.
 *
 * @param messageBit - The actual plaintext bit (0 or 1)
 * @param r - The encryption randomness used when creating ct
 * @param pubKey - The ElGamal public key
 * @param ct - The ciphertext to prove about
 */
export function proveBinary(
  ctx: ProofContext,
  messageBit: 0 | 1,
  r: Uint8Array,
  pubKey: Uint8Array,
  ct: Ciphertext,
): BinaryProof {
  return proveDisjunctive(BINARY_DOMAIN, requireContext(ctx), messageBit, r, pubKey, ct)
}

/**
 * Verifies, under `ctx`, a binary proof that a ciphertext encrypts 0 or 1.
 * Never throws: malformed input of any kind yields `false`.
 *
 * Checks:
 * 1. e0 + e1 = e  (challenges sum to the Fiat-Shamir challenge)
 * 2. g^z0 == a0 + c1*e0
 * 3. h^z0 == b0 + c2*e0
 * 4. g^z1 == a1 + c1*e1
 * 5. h^z1 == b1 + (c2 - g)*e1
 */
export function verifyBinary(ctx: ProofContext, pubKey: Uint8Array, ct: Ciphertext, p: BinaryProof): boolean {
  return verifyDisjunctive(BINARY_DOMAIN, ctx, pubKey, ct, p)
}

// ---------------------------------------------------------------------------
// Candidate-sum and consistency proofs (the disjunctive proof, own domains)
// ---------------------------------------------------------------------------

/**
 * Proves, bound to `ctx`, that a party's candidate vector sums to 0 or 1.
 * `aggCt` is the homomorphic sum of the candidate vector, `rSum` the sum of its
 * randomness. `ctx.index` is the party index p (ballot-proofs.md section 8.4).
 */
export function proveCandidateSum(
  ctx: ProofContext,
  sum: 0 | 1,
  rSum: Uint8Array,
  pubKey: Uint8Array,
  aggCt: Ciphertext,
): BinaryProof {
  return proveDisjunctive(CANDIDATE_SUM_DOMAIN, requireContext(ctx), sum, rSum, pubKey, aggCt)
}

/**
 * Verifies a candidate-sum proof under `ctx`. Never throws. `aggCt` is a
 * homomorphic sum, so either half may be the identity (see isAggregate).
 */
export function verifyCandidateSum(ctx: ProofContext, pubKey: Uint8Array, aggCt: Ciphertext, p: BinaryProof): boolean {
  return verifyDisjunctive(CANDIDATE_SUM_DOMAIN, ctx, pubKey, aggCt, p, isAggregate)
}

/**
 * Proves, bound to `ctx`, that party_bit − candidate_sum ∈ {0, 1}, as a
 * disjunctive proof over `partyCt − candSumCt`. `rDiff` is r_party − R_cand.
 * `ctx.index` is the party index p (ballot-proofs.md section 8.4).
 */
export function proveConsistency(
  ctx: ProofContext,
  diff: 0 | 1,
  rDiff: Uint8Array,
  pubKey: Uint8Array,
  partyCt: Ciphertext,
  candSumCt: Ciphertext,
): BinaryProof {
  const context = requireContext(ctx)
  return proveDisjunctive(CONSISTENCY_DOMAIN, context, diff, rDiff, pubKey, homomorphicSubtract(partyCt, candSumCt))
}

/**
 * Verifies a consistency proof under `ctx`. The difference ciphertext is
 * recomputed from `partyCt` and `candSumCt`. Never throws. `partyCt` is a
 * wire ciphertext; `candSumCt` is a homomorphic sum, so either half may be the
 * identity (see isAggregate).
 */
export function verifyConsistency(
  ctx: ProofContext,
  pubKey: Uint8Array,
  partyCt: Ciphertext,
  candSumCt: Ciphertext,
  p: BinaryProof,
): boolean {
  try {
    const context = contextOrNull(ctx)
    if (context === null) return false
    if (!isPoint(pubKey) || !isCiphertext(partyCt) || !isAggregate(candSumCt) || !isBinaryProof(p)) return false
    return disjunctiveEquationsHold(CONSISTENCY_DOMAIN, context, pubKey, homomorphicSubtract(partyCt, candSumCt), p)
  } catch {
    return false
  }
}

// ---------------------------------------------------------------------------
// Sum=1 proof (Schnorr)
// ---------------------------------------------------------------------------

export interface SumOneProof {
  a: Uint8Array  // 32 bytes — commitment
  b: Uint8Array  // 32 bytes
  z: Uint8Array  // 32 bytes — response
}

/**
 * Proves, bound to `ctx`, that a vector of ciphertexts encrypts values summing
 * to 1. Throws on an empty ID, an index that is not a uint32, or an empty vector.
 *
 * @param cts - The ciphertexts (caller ensures they encode a one-hot vector)
 * @param rSum - Pre-computed sum of all encryption randomness scalars
 * @param pubKey - The ElGamal public key
 */
export function proveSumOne(
  ctx: ProofContext,
  cts: Ciphertext[],
  rSum: Uint8Array,
  pubKey: Uint8Array,
): SumOneProof {
  const context = requireContext(ctx)
  requirePublicKey(SUM_DOMAIN, pubKey)
  const sodium = getSodium()

  const aggCt = homomorphicSum(cts)
  if (aggCt === null) throw new Error('Cannot prove sum of empty ciphertext list')

  const k = sodium.crypto_core_ristretto255_scalar_random()
  const a = sodium.crypto_scalarmult_ristretto255_base(k)
  const b = sodium.crypto_scalarmult_ristretto255(k, pubKey)

  const e = sumChallenge(context, pubKey, aggCt, a, b)

  // z = k + e*rSum
  const er = sodium.crypto_core_ristretto255_scalar_mul(e, rSum)
  const z = sodium.crypto_core_ristretto255_scalar_add(k, er)

  // Zero ephemeral nonce
  sodium.memzero(k)
  sodium.memzero(er)

  return { a, b, z }
}

/**
 * Verifies, under `ctx`, that a vector of ciphertexts encrypts values summing
 * to 1. Never throws: malformed input of any kind, including an empty vector,
 * yields `false`.
 *
 * Checks:
 * 1. g^z == a + aggC1 * e
 * 2. h^z == b + (aggC2 - g) * e
 */
export function verifySumOne(ctx: ProofContext, pubKey: Uint8Array, cts: Ciphertext[], p: SumOneProof): boolean {
  try {
    const context = contextOrNull(ctx)
    if (context === null) return false
    if (!isPoint(pubKey)) return false
    if (!Array.isArray(cts) || cts.length === 0 || !cts.every(isCiphertext)) return false
    if (!isPoint(p.a) || !isPoint(p.b) || !isCanonicalScalar(p.z)) return false

    const sodium = getSodium()
    const g = generatorPoint()

    const aggCt = homomorphicSum(cts)
    if (aggCt === null) return false

    const e = sumChallenge(context, pubKey, aggCt, p.a, p.b)

    // g^z == a + aggC1 * e
    const lhs1 = mulBase(p.z)
    const rhs1 = sodium.crypto_core_ristretto255_add(
      p.a,
      mul(e, aggCt.c1),
    )
    if (!bytesEqual(lhs1, rhs1)) return false

    // h^z == b + (aggC2 - g) * e
    const c2MinusG = sodium.crypto_core_ristretto255_sub(aggCt.c2, g)
    const lhs2 = mul(p.z, pubKey)
    const rhs2 = sodium.crypto_core_ristretto255_add(
      p.b,
      mul(e, c2MinusG),
    )
    return bytesEqual(lhs2, rhs2)
  } catch {
    return false
  }
}

// ---------------------------------------------------------------------------
// Internal helpers: the disjunctive proof shared by binary, candidate-sum and
// consistency proofs (Go: proveBinaryWithDomain / verifyBinaryWithDomain)
// ---------------------------------------------------------------------------

function proveDisjunctive(
  domain: string,
  context: Uint8Array[],
  messageBit: 0 | 1,
  r: Uint8Array,
  pubKey: Uint8Array,
  ct: Ciphertext,
): BinaryProof {
  requirePublicKey(domain, pubKey)
  if (messageBit === 0) return proveBinaryReal0(domain, context, r, pubKey, ct)
  if (messageBit === 1) return proveBinaryReal1(domain, context, r, pubKey, ct)
  throw new Error(`${domain}: claimed plaintext ${String(messageBit)} is not 0 or 1`)
}

function verifyDisjunctive(
  domain: string,
  ctx: ProofContext,
  pubKey: Uint8Array,
  ct: Ciphertext,
  p: BinaryProof,
  isStatement: (ct: Ciphertext) => boolean = isCiphertext,
): boolean {
  try {
    const context = contextOrNull(ctx)
    if (context === null) return false
    if (!isPoint(pubKey) || !isStatement(ct) || !isBinaryProof(p)) return false
    return disjunctiveEquationsHold(domain, context, pubKey, ct, p)
  } catch {
    return false
  }
}

/**
 * The verification equations of the disjunctive proof. Inputs are already
 * validated. Scalar-mults go through `mul`/`mulBase`, so an identity
 * intermediate is accepted exactly as Go accepts it; any other libsodium
 * exception is turned into `false` by every caller.
 */
function disjunctiveEquationsHold(
  domain: string,
  context: Uint8Array[],
  pubKey: Uint8Array,
  ct: Ciphertext,
  p: BinaryProof,
): boolean {
  const sodium = getSodium()
  const g = generatorPoint()

  const e = binaryChallenge(domain, context, pubKey, ct, p.a0, p.b0, p.a1, p.b1)

  // e0 + e1 == e, compared as reduced scalars
  const eSum = sodium.crypto_core_ristretto255_scalar_add(p.e0, p.e1)
  if (!bytesEqual(eSum, e)) return false

  // Branch 0: g^z0 == a0 + c1*e0
  const lhs0 = mulBase(p.z0)
  const rhs0 = sodium.crypto_core_ristretto255_add(
    p.a0,
    mul(p.e0, ct.c1),
  )
  if (!bytesEqual(lhs0, rhs0)) return false

  // Branch 0: h^z0 == b0 + c2*e0
  const lhs0b = mul(p.z0, pubKey)
  const rhs0b = sodium.crypto_core_ristretto255_add(
    p.b0,
    mul(p.e0, ct.c2),
  )
  if (!bytesEqual(lhs0b, rhs0b)) return false

  // Branch 1: g^z1 == a1 + c1*e1
  const lhs1 = mulBase(p.z1)
  const rhs1 = sodium.crypto_core_ristretto255_add(
    p.a1,
    mul(p.e1, ct.c1),
  )
  if (!bytesEqual(lhs1, rhs1)) return false

  // Branch 1: h^z1 == b1 + (c2 - g)*e1
  const c2MinusG = sodium.crypto_core_ristretto255_sub(ct.c2, g)
  const lhs1b = mul(p.z1, pubKey)
  const rhs1b = sodium.crypto_core_ristretto255_add(
    p.b1,
    mul(p.e1, c2MinusG),
  )
  return bytesEqual(lhs1b, rhs1b)
}

/** m=0 is real, m=1 is simulated */
function proveBinaryReal0(domain: string, context: Uint8Array[], r: Uint8Array, h: Uint8Array, ct: Ciphertext): BinaryProof {
  const sodium = getSodium()

  // Real branch 0
  const k = sodium.crypto_core_ristretto255_scalar_random()
  const a0 = sodium.crypto_scalarmult_ristretto255_base(k)   // g^k
  const b0 = sodium.crypto_scalarmult_ristretto255(k, h)     // h^k

  // Simulate branch 1: e1 and z1 are random
  const e1 = sodium.crypto_core_ristretto255_scalar_random()
  const z1 = sodium.crypto_core_ristretto255_scalar_random()

  // a1 = g^z1 - c1^e1. The statement points may be the identity (c1 of an
  // aggregate or a difference), so these scalar-mults go through `mul`.
  const gz1 = sodium.crypto_scalarmult_ristretto255_base(z1)
  const c1e1 = mul(e1, ct.c1)
  const a1 = sodium.crypto_core_ristretto255_sub(gz1, c1e1)

  // b1 = h^z1 - (c2 - g)^e1   [branch 1 assumes m=1, so c2 - g = h^r]
  const hz1 = mul(z1, h)
  const g = generatorPoint()
  const c2MinusG = sodium.crypto_core_ristretto255_sub(ct.c2, g)
  const c2ge1 = mul(e1, c2MinusG)
  const b1 = sodium.crypto_core_ristretto255_sub(hz1, c2ge1)

  // Challenge
  const e = binaryChallenge(domain, context, h, ct, a0, b0, a1, b1)

  // e0 = e - e1
  const e0 = sodium.crypto_core_ristretto255_scalar_sub(e, e1)

  // z0 = k + e0*r
  const e0r = sodium.crypto_core_ristretto255_scalar_mul(e0, r)
  const z0 = sodium.crypto_core_ristretto255_scalar_add(k, e0r)

  // Zero the ephemeral nonce and the witness-derived product
  sodium.memzero(k)
  sodium.memzero(e0r)

  return { a0, b0, a1, b1, e0, e1, z0, z1 }
}

/** m=1 is real, m=0 is simulated */
function proveBinaryReal1(domain: string, context: Uint8Array[], r: Uint8Array, h: Uint8Array, ct: Ciphertext): BinaryProof {
  const sodium = getSodium()

  // Simulate branch 0: e0 and z0 are random
  const e0 = sodium.crypto_core_ristretto255_scalar_random()
  const z0 = sodium.crypto_core_ristretto255_scalar_random()

  // a0 = g^z0 - c1^e0. The statement points may be the identity (c1 of an
  // aggregate or a difference), so these scalar-mults go through `mul`.
  const gz0 = sodium.crypto_scalarmult_ristretto255_base(z0)
  const c1e0 = mul(e0, ct.c1)
  const a0 = sodium.crypto_core_ristretto255_sub(gz0, c1e0)

  // b0 = h^z0 - c2^e0   [branch 0 assumes m=0, so c2 = h^r directly]
  const hz0 = mul(z0, h)
  const c2e0 = mul(e0, ct.c2)
  const b0 = sodium.crypto_core_ristretto255_sub(hz0, c2e0)

  // Real branch 1
  const k = sodium.crypto_core_ristretto255_scalar_random()
  const a1 = sodium.crypto_scalarmult_ristretto255_base(k)   // g^k
  const b1 = sodium.crypto_scalarmult_ristretto255(k, h)     // h^k

  // Challenge
  const e = binaryChallenge(domain, context, h, ct, a0, b0, a1, b1)

  // e1 = e - e0
  const e1 = sodium.crypto_core_ristretto255_scalar_sub(e, e0)

  // z1 = k + e1*r
  const e1r = sodium.crypto_core_ristretto255_scalar_mul(e1, r)
  const z1 = sodium.crypto_core_ristretto255_scalar_add(k, e1r)

  // Zero the ephemeral nonce and the witness-derived product
  sodium.memzero(k)
  sodium.memzero(e1r)

  return { a0, b0, a1, b1, e0, e1, z0, z1 }
}

/**
 * a − b component-wise; encrypts m_a − m_b with randomness r_a − r_b.
 * Mirrors Go's homomorphicSubtract (crypto/proof/candidate.go).
 */
function homomorphicSubtract(a: Ciphertext, b: Ciphertext): Ciphertext {
  const sodium = getSodium()
  return {
    c1: sodium.crypto_core_ristretto255_sub(a.c1, b.c1),
    c2: sodium.crypto_core_ristretto255_sub(a.c2, b.c2),
  }
}

// ---------------------------------------------------------------------------
// Verifier and prover arithmetic with Go's identity semantics
// ---------------------------------------------------------------------------

// libsodium's crypto_scalarmult_ristretto255(_base) refuses an identity result
// (it throws); Go's ScalarMult/ScalarBaseMult return the identity and carry on.
// crypto_core_ristretto255_add/sub already accept and return the identity
// encoding (32 zero bytes), so only the scalar-mults need wrapping. In this
// prime-order group s·P is the identity exactly when s ≡ 0 (mod ℓ) or P is the
// identity. Every scalar reaching these helpers is canonical (validated wire
// scalars, reduced challenges, or the provers' crypto_core_ristretto255_scalar_random
// output), so s ≡ 0 is exactly 32 zero bytes.

/** s·P, returning the identity encoding where libsodium would throw. */
function mul(s: Uint8Array, point: Uint8Array): Uint8Array {
  if (isAllZero(s) || isAllZero(point)) return new Uint8Array(32)
  return getSodium().crypto_scalarmult_ristretto255(s, point)
}

/** s·G, returning the identity encoding where libsodium would throw. */
function mulBase(s: Uint8Array): Uint8Array {
  if (isAllZero(s)) return new Uint8Array(32)
  return getSodium().crypto_scalarmult_ristretto255_base(s)
}

// ---------------------------------------------------------------------------
// Input validation for verifiers
// ---------------------------------------------------------------------------

function isBytes32(x: unknown): x is Uint8Array {
  return x instanceof Uint8Array && x.length === 32
}

function isAllZero(x: Uint8Array): boolean {
  return x.every(byte => byte === 0)
}

/**
 * A wire point: a 32-byte canonical Ristretto255 encoding that is not the
 * identity (32 zero bytes), as Go's group.DecodeElement requires.
 */
function isPoint(x: unknown): boolean {
  if (!isBytes32(x)) return false
  if (isAllZero(x)) return false
  return getSodium().crypto_core_ristretto255_is_valid_point(x)
}

/** A 32-byte little-endian scalar strictly below ℓ: reducing it changes nothing. */
function isCanonicalScalar(x: unknown): boolean {
  if (!isBytes32(x)) return false
  const wide = new Uint8Array(64)
  wide.set(x)
  return bytesEqual(getSodium().crypto_core_ristretto255_scalar_reduce(wide), x)
}

/**
 * A 32-byte canonical Ristretto255 encoding, the identity (32 zero bytes)
 * included. Only for values the verifier derives, never for wire fields.
 */
function isPointOrIdentity(x: unknown): boolean {
  if (!isBytes32(x)) return false
  return isAllZero(x) || getSodium().crypto_core_ristretto255_is_valid_point(x)
}

/** A wire ciphertext: both halves are wire points (isPoint). */
function isCiphertext(ct: Ciphertext): boolean {
  return isPoint(ct.c1) && isPoint(ct.c2)
}

/**
 * A ciphertext the verifier derives as a homomorphic sum (aggCt, candSumCt),
 * never a wire field. Randomness that sums to 0 mod ℓ makes c1 the identity
 * (and c2 too when the plaintext sum is 0); Go's VerifyCandidateSum and
 * VerifyConsistency only nil-check these, so the identity is allowed here.
 */
function isAggregate(ct: Ciphertext): boolean {
  return isPointOrIdentity(ct.c1) && isPointOrIdentity(ct.c2)
}

function isBinaryProof(p: BinaryProof): boolean {
  return isPoint(p.a0) && isPoint(p.b0) && isPoint(p.a1) && isPoint(p.b1) &&
    isCanonicalScalar(p.e0) && isCanonicalScalar(p.e1) &&
    isCanonicalScalar(p.z0) && isCanonicalScalar(p.z1)
}

/** Returns the Ristretto255 generator point (g^1). */
function generatorPoint(): Uint8Array {
  const sodium = getSodium()
  const one = new Uint8Array(32)
  one[0] = 1
  return sodium.crypto_scalarmult_ristretto255_base(one)
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}
