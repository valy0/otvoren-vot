import { getSodium } from './sodium'

// RFC 9162 Merkle tree hashing and proof verification. Mirrors Go's
// crypto/merkle (hash.go, verify.go); pinned to
// crypto/vectors/testdata/merkle.json. Verifiers return booleans and never
// throw. Indices and sizes are walked as BigInt: JS bitwise operators on
// numbers truncate to 32 bits.

export const HASH_SIZE = 32

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

function isHash(x: unknown): x is Uint8Array {
  return x instanceof Uint8Array && x.length === HASH_SIZE
}

function isHashList(xs: readonly unknown[]): xs is readonly Uint8Array[] {
  return Array.isArray(xs) && xs.every(isHash)
}

function isCount(x: unknown): x is number {
  return typeof x === 'number' && Number.isSafeInteger(x) && x >= 0
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
  if (!isCount(index) || !isCount(size)) return false
  if (!isHash(leaf) || !isHash(root) || !isHashList(proof)) return false
  if (index >= size) return false
  let fn = BigInt(index)
  let sn = BigInt(size) - 1n
  let r = leaf
  for (const p of proof) {
    if (sn === 0n) return false
    if ((fn & 1n) === 1n || fn === sn) {
      r = nodeHash(p, r)
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
  return equal(r, root)
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
  if (!isCount(size1) || !isCount(size2)) return false
  if (!isHash(root1) || !isHash(root2) || !isHashList(proof)) return false
  if (size1 > size2) return false
  if (size1 === 0 || size1 === size2) {
    if (proof.length !== 0) return false
    if (size1 === 0 && !equal(root1, emptyRoot())) return false
    if (size1 === size2 && !equal(root1, root2)) return false
    return true
  }
  if (proof.length === 0) return false
  const s1 = BigInt(size1)
  let start = proof[0]
  let rest = proof.slice(1)
  if ((s1 & (s1 - 1n)) === 0n) {
    start = root1
    rest = proof.slice(0)
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
  if (!equal(fr, root1)) return false
  if (!equal(sr, root2)) return false
  if (sn !== 0n) return false
  return true
}
