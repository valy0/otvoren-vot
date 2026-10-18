// Test-only constructions of proofs that hit the identity element or a zero
// scalar. Go's ScalarMult returns the identity for a zero scalar or an identity
// point and carries on; libsodium refuses such a result. Shared by
// proofs.test.ts and tsFixture.test.ts so the construction exists once.
import { getSodium } from '../sodium'
import { encryptWithRandomness, homomorphicSum, type Ciphertext } from '../elgamal'
import { fiatShamir } from '../fiatShamir'
import { proveSumOne, type BinaryProof, type ProofContext, type SumOneProof } from '../proofs'

export const ZERO = new Uint8Array(32)
export const ONE = new Uint8Array(32)
ONE[0] = 1
export const BINARY_DOMAIN = 'otvoren-vot.ballot-binary-proof'
export const CONSISTENCY_DOMAIN = 'otvoren-vot.candidate-consistency-proof'

export const isZero = (b: Uint8Array) => b.every(x => x === 0)

export const randomScalar = () => getSodium().crypto_core_ristretto255_scalar_random()

// Scalar-mults that return the identity encoding where libsodium throws.
function mulBaseOrIdentity(s: Uint8Array): Uint8Array {
  return isZero(s) ? new Uint8Array(32) : getSodium().crypto_scalarmult_ristretto255_base(s)
}
function mulOrIdentity(s: Uint8Array, point: Uint8Array): Uint8Array {
  return isZero(s) || isZero(point) ? new Uint8Array(32) : getSodium().crypto_scalarmult_ristretto255(s, point)
}

/** The context fields of docs/protocol/fiat-shamir.md, "Ballot-Proof Context". */
function contextFields(ctx: ProofContext): Uint8Array[] {
  const index = new Uint8Array(4)
  new DataView(index.buffer).setUint32(0, ctx.index, false)
  const utf8 = new TextEncoder()
  return [utf8.encode(ctx.electionId), utf8.encode(ctx.ballotId), index]
}

/**
 * The disjunctive proof built by hand, so that the simulated branch's
 * challenge `simE` and response `simZ` can be chosen. The provers draw them at
 * random and cannot multiply by a zero scalar or the identity. Branch m is real
 * (witness r); branch 1 − m is simulated.
 */
export function handBuiltDisjunctive(
  domain: string, ctx: ProofContext, pk: Uint8Array, ct: Ciphertext,
  m: 0 | 1, r: Uint8Array, simE: Uint8Array, simZ: Uint8Array,
): BinaryProof {
  const sodium = getSodium()
  const c2MinusG = sodium.crypto_core_ristretto255_sub(ct.c2, mulBaseOrIdentity(ONE))
  // The simulated branch's "c2" is c2 for branch 0 and c2 − g for branch 1.
  const simC2 = m === 0 ? c2MinusG : ct.c2
  const aSim = sodium.crypto_core_ristretto255_sub(mulBaseOrIdentity(simZ), mulOrIdentity(simE, ct.c1))
  const bSim = sodium.crypto_core_ristretto255_sub(mulOrIdentity(simZ, pk), mulOrIdentity(simE, simC2))
  const k = sodium.crypto_core_ristretto255_scalar_random()
  const aReal = mulBaseOrIdentity(k)
  const bReal = mulOrIdentity(k, pk)
  const [a0, b0, a1, b1] = m === 0 ? [aReal, bReal, aSim, bSim] : [aSim, bSim, aReal, bReal]
  const e = fiatShamir(domain, ...contextFields(ctx), pk, ct.c1, ct.c2, a0, b0, a1, b1)
  const eReal = sodium.crypto_core_ristretto255_scalar_sub(e, simE)
  const zReal = sodium.crypto_core_ristretto255_scalar_add(k, sodium.crypto_core_ristretto255_scalar_mul(eReal, r))
  return m === 0
    ? { a0, b0, a1, b1, e0: eReal, e1: simE, z0: zReal, z1: simZ }
    : { a0, b0, a1, b1, e0: simE, e1: eReal, z0: simZ, z1: zReal }
}

/**
 * A sum-one proof over [0, 1, 0] whose randomness sums to 0 mod ℓ, so the
 * aggregate c1 is the identity. Built through proveSumOne.
 */
export function zeroRandomnessSumOne(ctx: ProofContext, pk: Uint8Array): {
  cts: Ciphertext[]
  rSum: Uint8Array
  proof: SumOneProof
} {
  const sodium = getSodium()
  const r1 = randomScalar()
  const r2 = randomScalar()
  const r3 = sodium.crypto_core_ristretto255_scalar_negate(sodium.crypto_core_ristretto255_scalar_add(r1, r2))
  const cts = [encryptWithRandomness(0, r1, pk), encryptWithRandomness(1, r2, pk), encryptWithRandomness(0, r3, pk)]
  const rSum = sodium.crypto_core_ristretto255_scalar_add(sodium.crypto_core_ristretto255_scalar_add(r1, r2), r3)
  if (!isZero(rSum)) throw new Error('randomness does not sum to 0')
  if (!isZero(homomorphicSum(cts)?.c1 ?? ONE)) throw new Error('aggregate c1 is not the identity')
  return { cts, rSum, proof: proveSumOne(ctx, cts, rSum, pk) }
}
