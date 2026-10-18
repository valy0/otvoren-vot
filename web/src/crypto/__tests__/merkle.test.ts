import { readFileSync } from 'node:fs'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { bytesToHex, hexToBytes } from '../hex'
import {
  HASH_SIZE,
  emptyRoot,
  leafHash,
  nodeHash,
  verifyConsistency,
  verifyInclusion,
} from '../merkle'
import { initSodium } from '../sodium'

interface MerkleVectors {
  leaves_hex: string[]
  roots: { size: number; root_hex: string }[]
  inclusion: {
    index: number
    size: number
    leaf_hash_hex: string
    proof_hex: string[]
    root_hex: string
  }[]
  consistency: {
    size1: number
    size2: number
    root1_hex: string
    root2_hex: string
    proof_hex: string[]
  }[]
  invalid_inclusion: {
    case: string
    index: number
    size: number
    leaf_hash_hex: string
    proof_hex: string[]
    root_hex: string
  }[]
  invalid_consistency: {
    case: string
    size1: number
    size2: number
    root1_hex: string
    root2_hex: string
    proof_hex: string[]
  }[]
}

const vectors = JSON.parse(
  readFileSync(new URL('../../../../crypto/vectors/testdata/merkle.json', import.meta.url), 'utf8'),
) as MerkleVectors

beforeAll(async () => {
  await initSodium()
})

const h = (hex: string): Uint8Array => hexToBytes(hex)
const hs = (list: string[]): Uint8Array[] => list.map(h)

// Test-local RFC 9162 §2.1.1 MTH over leaf data.
function mth(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) return emptyRoot()
  if (leaves.length === 1) return leafHash(leaves[0])
  let k = 1
  while (k * 2 < leaves.length) k *= 2
  return nodeHash(mth(leaves.slice(0, k)), mth(leaves.slice(k)))
}

describe('hashing', () => {
  it('HASH_SIZE is 32', () => {
    expect(HASH_SIZE).toBe(32)
  })
  it('leafHash of empty data', () => {
    expect(bytesToHex(leafHash(new Uint8Array()))).toBe(
      '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
    )
  })
  it('emptyRoot is SHA-256 of nothing', () => {
    expect(bytesToHex(emptyRoot())).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    )
  })
  for (const r of vectors.roots) {
    it(`MTH of the first ${String(r.size)} leaves equals the Go root`, () => {
      const leaves = vectors.leaves_hex.slice(0, r.size).map(h)
      expect(bytesToHex(mth(leaves))).toBe(r.root_hex)
    })
  }
})

describe('verifyInclusion', () => {
  for (const v of vectors.inclusion) {
    it(`accepts index ${String(v.index)} of size ${String(v.size)}`, () => {
      expect(verifyInclusion(h(v.leaf_hash_hex), v.index, v.size, hs(v.proof_hex), h(v.root_hex))).toBe(true)
    })
  }
  for (const v of vectors.invalid_inclusion) {
    it(`rejects ${v.case}`, () => {
      expect(verifyInclusion(h(v.leaf_hash_hex), v.index, v.size, hs(v.proof_hex), h(v.root_hex))).toBe(false)
    })
  }
})

describe('verifyConsistency', () => {
  for (const v of vectors.consistency) {
    it(`accepts ${String(v.size1)} -> ${String(v.size2)}`, () => {
      expect(verifyConsistency(v.size1, v.size2, h(v.root1_hex), h(v.root2_hex), hs(v.proof_hex))).toBe(true)
    })
  }
  for (const v of vectors.invalid_consistency) {
    it(`rejects ${v.case}`, () => {
      expect(verifyConsistency(v.size1, v.size2, h(v.root1_hex), h(v.root2_hex), hs(v.proof_hex))).toBe(false)
    })
  }
})

describe('TS-only negatives never throw and return false', () => {
  const inc = vectors.inclusion.find(v => v.proof_hex.length > 0)
  const con = vectors.consistency.find(v => v.proof_hex.length > 0)
  if (!inc || !con) throw new Error('vectors lack a non-trivial proof')
  const incOk = (index: number, size: number, leaf = h(inc.leaf_hash_hex), proof = hs(inc.proof_hex), root = h(inc.root_hex)) =>
    verifyInclusion(leaf, index, size, proof, root)
  const conOk = (s1: number, s2: number, r1 = h(con.root1_hex), r2 = h(con.root2_hex), proof = hs(con.proof_hex)) =>
    verifyConsistency(s1, s2, r1, r2, proof)

  it('sanity: the base vectors verify', () => {
    expect(incOk(inc.index, inc.size)).toBe(true)
    expect(conOk(con.size1, con.size2)).toBe(true)
  })

  for (const bad of [-1, 1.5, NaN, 2 ** 53, Infinity]) {
    it(`rejects index/size ${String(bad)}`, () => {
      expect(incOk(bad, inc.size)).toBe(false)
      expect(incOk(inc.index, bad)).toBe(false)
      expect(conOk(bad, con.size2)).toBe(false)
      expect(conOk(con.size1, bad)).toBe(false)
    })
  }

  for (const len of [31, 33]) {
    const wrong = new Uint8Array(len)
    it(`rejects a ${String(len)}-byte hash anywhere`, () => {
      expect(incOk(inc.index, inc.size, wrong)).toBe(false)
      expect(incOk(inc.index, inc.size, undefined, undefined, wrong)).toBe(false)
      expect(incOk(inc.index, inc.size, undefined, [wrong, ...hs(inc.proof_hex).slice(1)])).toBe(false)
      expect(conOk(con.size1, con.size2, wrong)).toBe(false)
      expect(conOk(con.size1, con.size2, undefined, wrong)).toBe(false)
      expect(conOk(con.size1, con.size2, undefined, undefined, [wrong, ...hs(con.proof_hex).slice(1)])).toBe(false)
    })
  }

  it('rejects proof elements that are not a Uint8Array', () => {
    // A plain array holding the CORRECT bytes would verify if only the length were checked.
    const plain = (b: Uint8Array): Uint8Array => Array.from(b) as unknown as Uint8Array
    const ip = hs(inc.proof_hex)
    const cp = hs(con.proof_hex)
    const swapFirst = (xs: Uint8Array[], bad: Uint8Array): Uint8Array[] => [bad, ...xs.slice(1)]
    const nul = null as unknown as Uint8Array
    const str = 'aa'.repeat(32) as unknown as Uint8Array
    for (const mk of [plain, () => nul, () => str]) {
      expect(incOk(inc.index, inc.size, undefined, swapFirst(ip, mk(ip[0])))).toBe(false)
      expect(conOk(con.size1, con.size2, undefined, undefined, swapFirst(cp, mk(cp[0])))).toBe(false)
    }
  })

  it('rejects a sparse proof without throwing', () => {
    expect(incOk(0, 2, undefined, new Array<Uint8Array>(1))).toBe(false)
    expect(conOk(3, 8, undefined, undefined, new Array<Uint8Array>(1))).toBe(false)
    expect(conOk(4, 8, undefined, undefined, new Array<Uint8Array>(1))).toBe(false)
    const holed = (xs: Uint8Array[], at: number): Uint8Array[] => {
      const copy = [...xs]
      delete copy[at]
      return copy
    }
    const ip = hs(inc.proof_hex)
    for (let at = 0; at < ip.length; at++) expect(incOk(inc.index, inc.size, undefined, holed(ip, at))).toBe(false)
    const cp = hs(con.proof_hex)
    for (let at = 0; at < cp.length; at++) {
      expect(conOk(con.size1, con.size2, undefined, undefined, holed(cp, at))).toBe(false)
    }
  })

  // A verifier's result, or how it threw: a throw is a failure of its own.
  const outcome = (f: () => boolean): boolean | string => {
    try {
      return f()
    } catch (e) {
      return `threw ${String(e)}`
    }
  }
  // 64 bytes whose first 32 are the real hash, claiming length 32 through an
  // own length property or a subclass getter. TypedArray#set and libsodium
  // still see all 64 bytes.
  class LongerThanItSays extends Uint8Array {}
  Object.defineProperty(LongerThanItSays.prototype, 'length', { get: () => HASH_SIZE })
  const lying = (x: Uint8Array): Uint8Array[] => {
    const own = new Uint8Array(2 * HASH_SIZE).fill(0xff)
    own.set(x)
    Object.defineProperty(own, 'length', { value: HASH_SIZE })
    const sub = new LongerThanItSays(2 * HASH_SIZE).fill(0xff)
    sub.set(x)
    return [own, sub]
  }
  const replaced = (xs: Uint8Array[], at: number, x: Uint8Array): Uint8Array[] => {
    const copy = [...xs]
    copy[at] = x
    return copy
  }

  it('rejects a proof hash that claims length 32 but holds 64 bytes, without throwing', () => {
    for (const v of vectors.inclusion) {
      const proof = hs(v.proof_hex)
      for (let at = 0; at < proof.length; at++) {
        for (const bad of lying(proof[at])) {
          expect(outcome(() => incOk(v.index, v.size, h(v.leaf_hash_hex), replaced(proof, at, bad), h(v.root_hex)))).toBe(false)
        }
      }
    }
    for (const v of vectors.consistency) {
      const proof = hs(v.proof_hex)
      for (let at = 0; at < proof.length; at++) {
        for (const bad of lying(proof[at])) {
          expect(outcome(() => conOk(v.size1, v.size2, h(v.root1_hex), h(v.root2_hex), replaced(proof, at, bad)))).toBe(false)
        }
      }
    }
  })

  it('rejects a leaf or root that claims length 32 but holds 64 bytes, without throwing', () => {
    for (const v of vectors.inclusion) {
      const [leaf, proof, root] = [h(v.leaf_hash_hex), hs(v.proof_hex), h(v.root_hex)]
      for (const bad of lying(leaf)) expect(outcome(() => incOk(v.index, v.size, bad, proof, root))).toBe(false)
      for (const bad of lying(root)) expect(outcome(() => incOk(v.index, v.size, leaf, proof, bad))).toBe(false)
    }
    for (const v of vectors.consistency) {
      const [r1, r2, proof] = [h(v.root1_hex), h(v.root2_hex), hs(v.proof_hex)]
      for (const bad of lying(r1)) expect(outcome(() => conOk(v.size1, v.size2, bad, r2, proof))).toBe(false)
      for (const bad of lying(r2)) expect(outcome(() => conOk(v.size1, v.size2, r1, bad, proof))).toBe(false)
    }
  })

  it('rejects a proof of more than 64 hashes without reading it', () => {
    // No valid proof for safe-integer sizes is longer than 54 hashes.
    let reads = 0
    const long = new Array<Uint8Array>(65)
    Object.defineProperty(long, 0, {
      get: () => {
        reads++
        return h(inc.proof_hex[0])
      },
    })
    expect(incOk(inc.index, inc.size, undefined, long)).toBe(false)
    expect(conOk(con.size1, con.size2, undefined, undefined, long)).toBe(false)
    expect(reads).toBe(0)
    const sparse = new Array<Uint8Array>(1e7)
    expect(incOk(inc.index, inc.size, undefined, sparse)).toBe(false)
    expect(conOk(con.size1, con.size2, undefined, undefined, sparse)).toBe(false)
  })
})

describe('before initSodium', () => {
  it('both verifiers return false instead of throwing', async () => {
    // A fresh module graph: this sodium.ts has never been initialised.
    vi.resetModules()
    const fresh = await import('../sodium')
    const merkle = await import('../merkle')
    expect(() => fresh.getSodium()).toThrow()
    const inc = vectors.inclusion.find(v => v.proof_hex.length > 0)
    const con = vectors.consistency.find(v => v.size1 > 0 && v.proof_hex.length > 0)
    if (!inc || !con) throw new Error('vectors lack a non-trivial proof')
    const empty = h('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    const tryBoth = (f: () => boolean): boolean | string => {
      try {
        return f()
      } catch (e) {
        return `threw ${String(e)}`
      }
    }
    expect(
      tryBoth(() => merkle.verifyInclusion(h(inc.leaf_hash_hex), inc.index, inc.size, hs(inc.proof_hex), h(inc.root_hex))),
    ).toBe(false)
    expect(
      tryBoth(() => merkle.verifyConsistency(con.size1, con.size2, h(con.root1_hex), h(con.root2_hex), hs(con.proof_hex))),
    ).toBe(false)
    // The trivial cases hash too: the empty tree's head is computed.
    expect(tryBoth(() => merkle.verifyConsistency(0, 0, empty, empty, []))).toBe(false)
  })
})

describe('vector file', () => {
  it('has every category non-empty', () => {
    expect(vectors.leaves_hex.length).toBeGreaterThan(0)
    expect(vectors.roots.length).toBeGreaterThan(0)
    expect(vectors.inclusion.length).toBeGreaterThan(0)
    expect(vectors.consistency.length).toBeGreaterThan(0)
    expect(vectors.invalid_inclusion.length).toBeGreaterThan(0)
    expect(vectors.invalid_consistency.length).toBeGreaterThan(0)
  })
})
