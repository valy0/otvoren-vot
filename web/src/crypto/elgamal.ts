import { getSodium } from './sodium'
import { bytesToHex, hexToBytes } from './hex'

export interface Ciphertext {
  c1: Uint8Array  // 32 bytes — g^r
  c2: Uint8Array  // 32 bytes — h^r + g^m
}

export interface EncryptionResult {
  ciphertext: Ciphertext
  /** 32-byte scalar. Zero this out after proof generation. */
  randomness: Uint8Array
}

/**
 * Encrypts a single bit (0 or 1) under the given public key.
 *
 * c1 = g^r
 * c2 = h^r + g^m
 *   m=0: c2 = h^r  (adding identity)
 *   m=1: c2 = h^r + g
 */
export function encrypt(messageBit: 0 | 1, pubKey: Uint8Array): EncryptionResult {
  const r = getSodium().crypto_core_ristretto255_scalar_random()
  return {
    ciphertext: encryptWithRandomness(messageBit, r, pubKey),
    randomness: r,
  }
}

/**
 * Encrypts a single bit (0 or 1) under the given public key with the caller's
 * randomness `r`: c1 = g^r, c2 = h^r + g^m. Mirrors Go's
 * elgamal.EncryptWithRandomness; used for deterministic test vectors.
 * Throws unless messageBit is exactly 0 or 1 and r is a canonical scalar
 * (libsodium's scalarmult clears bit 255 of r while its scalar arithmetic
 * reduces r mod ℓ, so a non-canonical r would give a ciphertext that does not
 * match the randomness the proofs use). A zero r makes libsodium throw, as Go
 * refuses it: c1 would be the identity and reveal m.
 */
export function encryptWithRandomness(messageBit: 0 | 1, r: Uint8Array, pubKey: Uint8Array): Ciphertext {
  if (messageBit !== 0 && messageBit !== 1) {
    throw new Error(`messageBit must be 0 or 1, got ${String(messageBit)}`)
  }
  if (!isCanonicalScalar(r)) {
    throw new Error('Encryption randomness must be a canonical 32-byte scalar (< ℓ)')
  }
  const sodium = getSodium()
  const c1 = sodium.crypto_scalarmult_ristretto255_base(r)
  const hr = sodium.crypto_scalarmult_ristretto255(r, pubKey)

  if (messageBit === 0) {
    return { c1, c2: hr }
  }
  // g^1 = generator point
  const g = sodium.crypto_scalarmult_ristretto255_base(scalarOne())
  return { c1, c2: sodium.crypto_core_ristretto255_add(hr, g) }
}

/**
 * Adds two ciphertexts homomorphically.
 * Result encrypts the sum of the two plaintexts.
 */
export function homomorphicAdd(a: Ciphertext, b: Ciphertext): Ciphertext {
  const sodium = getSodium()
  return {
    c1: sodium.crypto_core_ristretto255_add(a.c1, b.c1),
    c2: sodium.crypto_core_ristretto255_add(a.c2, b.c2),
  }
}

/**
 * Adds all ciphertexts homomorphically.
 * Returns null for empty input.
 */
export function homomorphicSum(cts: Ciphertext[]): Ciphertext | null {
  if (cts.length === 0) return null
  let result = cts[0]
  for (let i = 1; i < cts.length; i++) {
    result = homomorphicAdd(result, cts[i])
  }
  return result
}

/**
 * Serializes a ciphertext to 128 lowercase hex characters (no prefix).
 * Format: c1 (64 hex chars) || c2 (64 hex chars)
 */
export function serializeCiphertext(ct: Ciphertext): string {
  return bytesToHex(ct.c1) + bytesToHex(ct.c2)
}

/**
 * Deserializes a ciphertext from 128 lowercase hex characters.
 */
export function deserializeCiphertext(hex: string): Ciphertext {
  if (hex.length !== 128) {
    throw new Error(`Expected 128 hex chars, got ${hex.length}`)
  }
  return {
    c1: hexToBytes(hex.slice(0, 64)),
    c2: hexToBytes(hex.slice(64, 128)),
  }
}

export { bytesToHex, hexToBytes }

/**
 * A 32-byte little-endian scalar strictly below ℓ: reducing it changes
 * nothing. Go's group.DecodeScalar accepts exactly these.
 */
export function isCanonicalScalar(x: unknown): x is Uint8Array {
  if (!(x instanceof Uint8Array) || x.length !== 32) return false
  const wide = new Uint8Array(64)
  wide.set(x)
  const reduced = getSodium().crypto_core_ristretto255_scalar_reduce(wide)
  return reduced.every((byte, i) => byte === x[i])
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Returns the scalar value 1 as a 32-byte little-endian Uint8Array. */
function scalarOne(): Uint8Array {
  // Ristretto255 scalars are little-endian: byte 0 = 1, rest = 0.
  const one = new Uint8Array(32)
  one[0] = 1
  return one
}
