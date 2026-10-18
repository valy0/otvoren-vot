import { getSodium } from './sodium'

// RFC 9162 Merkle tree hashing and proof verification. Mirrors Go's
// crypto/merkle (hash.go, verify.go); pinned to
// crypto/vectors/testdata/merkle.json. Verifiers return booleans and never
// throw, like proofs.ts, even before initSodium(). Indices and sizes are
// walked as BigInt: JS bitwise operators on numbers truncate to 32 bits.

export const HASH_SIZE = 32

// No valid proof for safe-integer sizes is longer than 54 hashes. A longer
// proof is rejected before any of its elements is read.
const MAX_PROOF_LENGTH = 64

function sha256Prefixed(prefix: number, ...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 1)
  const buf = new Uint8Array(total)
  buf[0] = prefix
  let off = 1
  for (const p of parts) {
    buf.set(p, off)
    off += p.length
  }
  return getSodium().crypto_hash_sha256(buf)
}

/** SHA-256(0x00 || data), the hash of a leaf (RFC 9162 section 2.1.1). */
export function leafHash(data: Uint8Array): Uint8Array {
  return sha256Prefixed(0x00, data)
}

/** SHA-256(0x01 || left || right), the hash of an interior node. */
export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256Prefixed(0x01, left, right)
}

/** SHA-256 of the empty string, the head of the empty tree. */
export function emptyRoot(): Uint8Array {
  return getSodium().crypto_hash_sha256(new Uint8Array())
}

function isCount(x: unknown): x is number {
  return typeof x === 'number' && Number.isSafeInteger(x) && x >= 0
}

// The intrinsic %TypedArray%.prototype.length getter. It reads the internal
// length, which neither an own `length` property nor a subclass getter can
// change.
const intrinsicLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'length')?.get

/**
 * A private copy of x, or null unless x is a Uint8Array of exactly 32 bytes by
 * its internal length. The verifiers hash and compare only such copies.
 */
function copyHash(x: unknown): Uint8Array | null {
  if (!(x instanceof Uint8Array) || intrinsicLength === undefined) return null
  if (intrinsicLength.call(x) !== HASH_SIZE) return null
  const copy = new Uint8Array(HASH_SIZE)
  copy.set(x)
  return copy
}

/**
 * One dense snapshot of the caller's proof as copyHash copies, so the walk
 * never reads the caller's array or its elements again. Its length is read
 * once and each index once: a hole reads as undefined and fails copyHash.
 * Null when proof is not an array of at most MAX_PROOF_LENGTH 32-byte
 * Uint8Arrays.
 */
function snapshotProof(proof: readonly Uint8Array[]): Uint8Array[] | null {
  if (!Array.isArray(proof)) return null
  const length: unknown = proof.length
  if (!isCount(length) || length > MAX_PROOF_LENGTH) return null
  const path: Uint8Array[] = []
  for (let i = 0; i < length; i++) {
    const copy = copyHash(proof[i])
    if (copy === null) return null
    path.push(copy)
  }
  return path
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

/**
 * Checks that leaf is leaf `index` of the tree of `size` leaves with head
 * `root`, given its audit path (RFC 9162 section 2.1.3.2).
 */
export function verifyInclusion(
  leaf: Uint8Array,
  index: number,
  size: number,
  proof: readonly Uint8Array[],
  root: Uint8Array,
): boolean {
  try {
    if (!isCount(index) || !isCount(size)) return false
    const leafCopy = copyHash(leaf)
    const rootCopy = copyHash(root)
    const path = snapshotProof(proof)
    if (leafCopy === null || rootCopy === null || path === null) return false
    if (index >= size) return false
    let fn = BigInt(index)
    let sn = BigInt(size) - 1n
    let r = leafCopy
    for (const p of path) {
      if (sn === 0n) return false
      if ((fn & 1n) === 1n || fn === sn) {
        r = nodeHash(p, r)
        // The fn !== 0n exit is unreachable while the sn === 0n check stands (RFC 9162 erratum 8670).
        while ((fn & 1n) === 0n && fn !== 0n) {
          fn >>= 1n
          sn >>= 1n
        }
      } else {
        r = nodeHash(r, p)
      }
      fn >>= 1n
      sn >>= 1n
    }
    if (sn !== 0n) return false
    return equal(r, rootCopy)
  } catch {
    return false
  }
}

/**
 * Checks that the tree of `size1` leaves with head `root1` is a prefix of the
 * tree of `size2` leaves with head `root2` (RFC 9162 section 2.1.4.2, plus
 * the trivial cases of docs/protocol/merkle.md).
 */
export function verifyConsistency(
  size1: number,
  size2: number,
  root1: Uint8Array,
  root2: Uint8Array,
  proof: readonly Uint8Array[],
): boolean {
  try {
    if (!isCount(size1) || !isCount(size2)) return false
    const root1Copy = copyHash(root1)
    const root2Copy = copyHash(root2)
    const path = snapshotProof(proof)
    if (root1Copy === null || root2Copy === null || path === null) return false
    if (size1 > size2) return false
    if (size1 === 0 || size1 === size2) {
      if (path.length !== 0) return false
      if (size1 === 0 && !equal(root1Copy, emptyRoot())) return false
      if (size1 === size2 && !equal(root1Copy, root2Copy)) return false
      return true
    }
    if (path.length === 0) return false
    const s1 = BigInt(size1)
    let start = path[0]
    let rest = path.slice(1)
    if ((s1 & (s1 - 1n)) === 0n) {
      start = root1Copy
      rest = path
    }
    let fn = s1 - 1n
    let sn = BigInt(size2) - 1n
    while ((fn & 1n) === 1n) {
      fn >>= 1n
      sn >>= 1n
    }
    let fr = start
    let sr = start
    for (const c of rest) {
      if (sn === 0n) return false
      if ((fn & 1n) === 1n || fn === sn) {
        fr = nodeHash(c, fr)
        sr = nodeHash(c, sr)
        // The fn !== 0n exit is unreachable while the sn === 0n check stands (RFC 9162 erratum 8670).
        while ((fn & 1n) === 0n && fn !== 0n) {
          fn >>= 1n
          sn >>= 1n
        }
      } else {
        sr = nodeHash(sr, c)
      }
      fn >>= 1n
      sn >>= 1n
    }
    if (!equal(fr, root1Copy)) return false
    if (!equal(sr, root2Copy)) return false
    if (sn !== 0n) return false
    return true
  } catch {
    return false
  }
}
