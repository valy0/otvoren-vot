import { getSodium } from './sodium'
import { fiatShamir } from './fiatShamir'
import { type Ciphertext, homomorphicSum } from './elgamal'

const BINARY_DOMAIN = 'otvoren-vot.ballot-binary-proof'
const SUM_DOMAIN = 'otvoren-vot.ballot-sum-proof'

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
 * Proves that `ct` encrypts 0 or 1 using a disjunctive Chaum-Pedersen proof.
 *
 * @param messageBit - The actual plaintext bit (0 or 1)
 * @param r - The encryption randomness used when creating ct
 * @param pubKey - The ElGamal public key
 * @param ct - The ciphertext to prove about
 */
export function proveBinary(
  messageBit: 0 | 1,
  r: Uint8Array,
  pubKey: Uint8Array,
  ct: Ciphertext,
): BinaryProof {
  if (messageBit === 0) {
    return proveBinaryReal0(r, pubKey, ct)
  }
  return proveBinaryReal1(r, pubKey, ct)
}

/**
 * Verifies a binary proof that a ciphertext encrypts 0 or 1.
 *
 * Checks:
 * 1. e0 + e1 = e  (challenges sum to the Fiat-Shamir challenge)
 * 2. g^z0 == a0 + c1*e0
 * 3. h^z0 == b0 + c2*e0
 * 4. g^z1 == a1 + c1*e1
 * 5. h^z1 == b1 + (c2 - g)*e1
 */
export function verifyBinary(pubKey: Uint8Array, ct: Ciphertext, p: BinaryProof): boolean {
  const sodium = getSodium()
  const g = generatorPoint()

  const e = fiatShamir(BINARY_DOMAIN, pubKey, ct.c1, ct.c2, p.a0, p.b0, p.a1, p.b1)

  // Check e0 + e1 == e
  const eSum = sodium.crypto_core_ristretto255_scalar_add(p.e0, p.e1)
  if (!bytesEqual(eSum, e)) return false

  // Branch 0: g^z0 == a0 + c1*e0
  const lhs0 = sodium.crypto_scalarmult_ristretto255_base(p.z0)
  const rhs0 = sodium.crypto_core_ristretto255_add(
    p.a0,
    sodium.crypto_scalarmult_ristretto255(p.e0, ct.c1),
  )
  if (!bytesEqual(lhs0, rhs0)) return false

  // Branch 0: h^z0 == b0 + c2*e0
  const lhs0b = sodium.crypto_scalarmult_ristretto255(p.z0, pubKey)
  const rhs0b = sodium.crypto_core_ristretto255_add(
    p.b0,
    sodium.crypto_scalarmult_ristretto255(p.e0, ct.c2),
  )
  if (!bytesEqual(lhs0b, rhs0b)) return false

  // Branch 1: g^z1 == a1 + c1*e1
  const lhs1 = sodium.crypto_scalarmult_ristretto255_base(p.z1)
  const rhs1 = sodium.crypto_core_ristretto255_add(
    p.a1,
    sodium.crypto_scalarmult_ristretto255(p.e1, ct.c1),
  )
  if (!bytesEqual(lhs1, rhs1)) return false

  // Branch 1: h^z1 == b1 + (c2 - g)*e1
  const c2MinusG = sodium.crypto_core_ristretto255_sub(ct.c2, g)
  const lhs1b = sodium.crypto_scalarmult_ristretto255(p.z1, pubKey)
  const rhs1b = sodium.crypto_core_ristretto255_add(
    p.b1,
    sodium.crypto_scalarmult_ristretto255(p.e1, c2MinusG),
  )
  if (!bytesEqual(lhs1b, rhs1b)) return false

  return true
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
 * Proves that a vector of ciphertexts encrypts values summing to 1.
 *
 * @param cts - The ciphertexts (caller ensures they encode a one-hot vector)
 * @param rSum - Pre-computed sum of all encryption randomness scalars
 * @param pubKey - The ElGamal public key
 */
export function proveSumOne(
  cts: Ciphertext[],
  rSum: Uint8Array,
  pubKey: Uint8Array,
): SumOneProof {
  const sodium = getSodium()

  const aggCt = homomorphicSum(cts)
  if (aggCt === null) throw new Error('Cannot prove sum of empty ciphertext list')

  const k = sodium.crypto_core_ristretto255_scalar_random()
  const a = sodium.crypto_scalarmult_ristretto255_base(k)
  const b = sodium.crypto_scalarmult_ristretto255(k, pubKey)

  const e = fiatShamir(SUM_DOMAIN, pubKey, aggCt.c1, aggCt.c2, a, b)

  // z = k + e*rSum
  const er = sodium.crypto_core_ristretto255_scalar_mul(e, rSum)
  const z = sodium.crypto_core_ristretto255_scalar_add(k, er)

  return { a, b, z }
}

/**
 * Verifies that a vector of ciphertexts encrypts values summing to 1.
 *
 * Checks:
 * 1. g^z == a + aggC1 * e
 * 2. h^z == b + (aggC2 - g) * e
 */
export function verifySumOne(pubKey: Uint8Array, cts: Ciphertext[], p: SumOneProof): boolean {
  const sodium = getSodium()
  const g = generatorPoint()

  const aggCt = homomorphicSum(cts)
  if (aggCt === null) return false

  const e = fiatShamir(SUM_DOMAIN, pubKey, aggCt.c1, aggCt.c2, p.a, p.b)

  // g^z == a + aggC1 * e
  const lhs1 = sodium.crypto_scalarmult_ristretto255_base(p.z)
  const rhs1 = sodium.crypto_core_ristretto255_add(
    p.a,
    sodium.crypto_scalarmult_ristretto255(e, aggCt.c1),
  )
  if (!bytesEqual(lhs1, rhs1)) return false

  // h^z == b + (aggC2 - g) * e
  const c2MinusG = sodium.crypto_core_ristretto255_sub(aggCt.c2, g)
  const lhs2 = sodium.crypto_scalarmult_ristretto255(p.z, pubKey)
  const rhs2 = sodium.crypto_core_ristretto255_add(
    p.b,
    sodium.crypto_scalarmult_ristretto255(e, c2MinusG),
  )
  if (!bytesEqual(lhs2, rhs2)) return false

  return true
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** m=0 is real, m=1 is simulated */
function proveBinaryReal0(r: Uint8Array, h: Uint8Array, ct: Ciphertext): BinaryProof {
  const sodium = getSodium()

  // Real branch 0
  const k = sodium.crypto_core_ristretto255_scalar_random()
  const a0 = sodium.crypto_scalarmult_ristretto255_base(k)   // g^k
  const b0 = sodium.crypto_scalarmult_ristretto255(k, h)     // h^k

  // Simulate branch 1: e1 and z1 are random
  const e1 = sodium.crypto_core_ristretto255_scalar_random()
  const z1 = sodium.crypto_core_ristretto255_scalar_random()

  // a1 = g^z1 - c1^e1
  const gz1 = sodium.crypto_scalarmult_ristretto255_base(z1)
  const c1e1 = sodium.crypto_scalarmult_ristretto255(e1, ct.c1)
  const a1 = sodium.crypto_core_ristretto255_sub(gz1, c1e1)

  // b1 = h^z1 - (c2 - g)^e1   [branch 1 assumes m=1, so c2 - g = h^r]
  const hz1 = sodium.crypto_scalarmult_ristretto255(z1, h)
  const g = generatorPoint()
  const c2MinusG = sodium.crypto_core_ristretto255_sub(ct.c2, g)
  const c2ge1 = sodium.crypto_scalarmult_ristretto255(e1, c2MinusG)
  const b1 = sodium.crypto_core_ristretto255_sub(hz1, c2ge1)

  // Challenge
  const e = fiatShamir(BINARY_DOMAIN, h, ct.c1, ct.c2, a0, b0, a1, b1)

  // e0 = e - e1
  const e0 = sodium.crypto_core_ristretto255_scalar_sub(e, e1)

  // z0 = k + e0*r
  const e0r = sodium.crypto_core_ristretto255_scalar_mul(e0, r)
  const z0 = sodium.crypto_core_ristretto255_scalar_add(k, e0r)

  return { a0, b0, a1, b1, e0, e1, z0, z1 }
}

/** m=1 is real, m=0 is simulated */
function proveBinaryReal1(r: Uint8Array, h: Uint8Array, ct: Ciphertext): BinaryProof {
  const sodium = getSodium()

  // Simulate branch 0: e0 and z0 are random
  const e0 = sodium.crypto_core_ristretto255_scalar_random()
  const z0 = sodium.crypto_core_ristretto255_scalar_random()

  // a0 = g^z0 - c1^e0
  const gz0 = sodium.crypto_scalarmult_ristretto255_base(z0)
  const c1e0 = sodium.crypto_scalarmult_ristretto255(e0, ct.c1)
  const a0 = sodium.crypto_core_ristretto255_sub(gz0, c1e0)

  // b0 = h^z0 - c2^e0   [branch 0 assumes m=0, so c2 = h^r directly]
  const hz0 = sodium.crypto_scalarmult_ristretto255(z0, h)
  const c2e0 = sodium.crypto_scalarmult_ristretto255(e0, ct.c2)
  const b0 = sodium.crypto_core_ristretto255_sub(hz0, c2e0)

  // Real branch 1
  const k = sodium.crypto_core_ristretto255_scalar_random()
  const a1 = sodium.crypto_scalarmult_ristretto255_base(k)   // g^k
  const b1 = sodium.crypto_scalarmult_ristretto255(k, h)     // h^k

  // Challenge
  const e = fiatShamir(BINARY_DOMAIN, h, ct.c1, ct.c2, a0, b0, a1, b1)

  // e1 = e - e0
  const e1 = sodium.crypto_core_ristretto255_scalar_sub(e, e0)

  // z1 = k + e1*r
  const e1r = sodium.crypto_core_ristretto255_scalar_mul(e1, r)
  const z1 = sodium.crypto_core_ristretto255_scalar_add(k, e1r)

  return { a0, b0, a1, b1, e0, e1, z0, z1 }
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
