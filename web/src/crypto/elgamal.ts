import { getSodium } from './sodium'

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
  const sodium = getSodium()
  const r = sodium.crypto_core_ristretto255_scalar_random()
  const c1 = sodium.crypto_scalarmult_ristretto255_base(r)
  const hr = sodium.crypto_scalarmult_ristretto255(r, pubKey)

  let c2: Uint8Array
  if (messageBit === 0) {
    c2 = hr
  } else {
    // g^1 = generator point
    const g = sodium.crypto_scalarmult_ristretto255_base(scalarOne())
    c2 = sodium.crypto_core_ristretto255_add(hr, g)
  }

  return {
    ciphertext: { c1, c2 },
    randomness: r,
  }
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

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Hex string must have even length')
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
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
