import { readFileSync } from 'node:fs'
import { beforeAll, describe, expect, it } from 'vitest'
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
