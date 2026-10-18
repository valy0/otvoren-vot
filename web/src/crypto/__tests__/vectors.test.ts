// Cross-language vectors: the browser must reproduce and verify exactly what
// the Go side (crypto/vectors) generates. The schema is documented on the Go
// side in crypto/vectors/vectors_test.go; every binary value is lowercase hex.
import { readFileSync } from 'node:fs'
import { describe, it, expect, beforeAll } from 'vitest'
import { initSodium, getSodium } from '../sodium'
import { encryptWithRandomness, hexToBytes, bytesToHex, type Ciphertext } from '../elgamal'
import { fiatShamir } from '../fiatShamir'
import {
  verifyBinary,
  verifySumOne,
  verifyCandidateSum,
  verifyConsistency,
  type BinaryProof,
  type ProofContext,
  type SumOneProof,
} from '../proofs'

interface ContextJson { election_id: string; ballot_id: string; index: number }
interface CiphertextJson { c1_hex: string; c2_hex: string }
interface BinaryProofJson {
  a0_hex: string; b0_hex: string; a1_hex: string; b1_hex: string
  e0_hex: string; e1_hex: string; z0_hex: string; z1_hex: string
}
interface SumOneProofJson { a_hex: string; b_hex: string; z_hex: string }

interface Vectors {
  scalar_base_mult: { scalar_hex: string; expected_point_hex: string }[]
  elgamal_encrypt: {
    public_key_hex: string
    randomness_hex: string
    message: number
    expected_c1_hex: string
    expected_c2_hex: string
  }[]
  fiat_shamir: { domain: string; data_hex: string[]; expected_scalar_hex: string }[]
  binary_proof: {
    context: ContextJson
    public_key_hex: string
    message: number
    ciphertext_c1_hex: string
    ciphertext_c2_hex: string
    proof: BinaryProofJson
  }[]
  sum_one_proof: {
    context: ContextJson
    public_key_hex: string
    ciphertexts: CiphertextJson[]
    proof: SumOneProofJson
  }[]
  candidate_sum_proof: {
    context: ContextJson
    public_key_hex: string
    agg_c1_hex: string
    agg_c2_hex: string
    sum: number
    proof: BinaryProofJson
  }[]
  consistency_proof: {
    context: ContextJson
    public_key_hex: string
    party_ciphertext: CiphertextJson
    cand_sum_ciphertext: CiphertextJson
    diff: number
    proof: BinaryProofJson
  }[]
}

const vectors = JSON.parse(
  readFileSync(new URL('../../../../crypto/vectors/testdata/vectors.json', import.meta.url), 'utf8'),
) as Vectors

beforeAll(async () => {
  await initSodium()
})

function toBit(n: number): 0 | 1 {
  if (n !== 0 && n !== 1) throw new Error(`expected a bit, got ${n}`)
  return n
}

function toCtx(c: ContextJson): ProofContext {
  return { electionId: c.election_id, ballotId: c.ballot_id, index: c.index }
}

function toCiphertext(c: CiphertextJson): Ciphertext {
  return { c1: hexToBytes(c.c1_hex), c2: hexToBytes(c.c2_hex) }
}

function toBinaryProof(p: BinaryProofJson): BinaryProof {
  return {
    a0: hexToBytes(p.a0_hex), b0: hexToBytes(p.b0_hex),
    a1: hexToBytes(p.a1_hex), b1: hexToBytes(p.b1_hex),
    e0: hexToBytes(p.e0_hex), e1: hexToBytes(p.e1_hex),
    z0: hexToBytes(p.z0_hex), z1: hexToBytes(p.z1_hex),
  }
}

function toSumOneProof(p: SumOneProofJson): SumOneProof {
  return { a: hexToBytes(p.a_hex), b: hexToBytes(p.b_hex), z: hexToBytes(p.z_hex) }
}

function isAscii(s: string): boolean {
  return Array.from(s).every(ch => (ch.codePointAt(0) ?? 0) < 0x80)
}

type ProofKind = 'binary' | 'sum-one' | 'candidate-sum' | 'consistency'
const PROOF_KINDS: readonly ProofKind[] = ['binary', 'sum-one', 'candidate-sum', 'consistency']

/** One Go-generated ballot proof, with a verifier closed over its statement. */
interface ProofCase {
  kind: ProofKind
  name: string
  ctx: ProofContext
  verify: (ctx: ProofContext) => boolean
}

const proofCases: ProofCase[] = [
  ...vectors.binary_proof.map((v, i): ProofCase => {
    const pk = hexToBytes(v.public_key_hex)
    const ct = { c1: hexToBytes(v.ciphertext_c1_hex), c2: hexToBytes(v.ciphertext_c2_hex) }
    const p = toBinaryProof(v.proof)
    return { kind: 'binary', name: `binary_proof[${i}]`, ctx: toCtx(v.context), verify: c => verifyBinary(c, pk, ct, p) }
  }),
  ...vectors.sum_one_proof.map((v, i): ProofCase => {
    const pk = hexToBytes(v.public_key_hex)
    const cts = v.ciphertexts.map(toCiphertext)
    const p = toSumOneProof(v.proof)
    return { kind: 'sum-one', name: `sum_one_proof[${i}]`, ctx: toCtx(v.context), verify: c => verifySumOne(c, pk, cts, p) }
  }),
  ...vectors.candidate_sum_proof.map((v, i): ProofCase => {
    const pk = hexToBytes(v.public_key_hex)
    const agg = { c1: hexToBytes(v.agg_c1_hex), c2: hexToBytes(v.agg_c2_hex) }
    const p = toBinaryProof(v.proof)
    return {
      kind: 'candidate-sum', name: `candidate_sum_proof[${i}]`, ctx: toCtx(v.context),
      verify: c => verifyCandidateSum(c, pk, agg, p),
    }
  }),
  ...vectors.consistency_proof.map((v, i): ProofCase => {
    const pk = hexToBytes(v.public_key_hex)
    const partyCt = toCiphertext(v.party_ciphertext)
    const candSumCt = toCiphertext(v.cand_sum_ciphertext)
    const p = toBinaryProof(v.proof)
    return {
      kind: 'consistency', name: `consistency_proof[${i}]`, ctx: toCtx(v.context),
      verify: c => verifyConsistency(c, pk, partyCt, candSumCt, p),
    }
  }),
]

// A ballot ID no vector uses: the example value of docs/protocol/fiat-shamir.md.
const OTHER_BALLOT_ID = 'Zm9yLXRoZS1leGFtcGxlLW9ubHktMzItYnl0ZXMtISE'

describe('Go vectors: primitives', () => {
  it('has vectors of every primitive kind', () => {
    expect(vectors.scalar_base_mult.length).toBeGreaterThan(0)
    expect(vectors.elgamal_encrypt.length).toBeGreaterThan(0)
    expect(vectors.fiat_shamir.length).toBeGreaterThan(0)
  })

  for (const [i, v] of vectors.scalar_base_mult.entries()) {
    it(`scalar_base_mult[${i}] equals the expected point`, () => {
      const point = getSodium().crypto_scalarmult_ristretto255_base(hexToBytes(v.scalar_hex))
      expect(bytesToHex(point)).toBe(v.expected_point_hex)
    })
  }

  for (const [i, v] of vectors.elgamal_encrypt.entries()) {
    it(`elgamal_encrypt[${i}] equals the expected ciphertext`, () => {
      const ct = encryptWithRandomness(toBit(v.message), hexToBytes(v.randomness_hex), hexToBytes(v.public_key_hex))
      expect(bytesToHex(ct.c1)).toBe(v.expected_c1_hex)
      expect(bytesToHex(ct.c2)).toBe(v.expected_c2_hex)
    })
  }

  for (const [i, v] of vectors.fiat_shamir.entries()) {
    it(`fiat_shamir[${i}] equals the expected challenge`, () => {
      const e = fiatShamir(v.domain, ...v.data_hex.map(hexToBytes))
      expect(bytesToHex(e)).toBe(v.expected_scalar_hex)
    })
  }
})

describe('Go vectors: ballot proofs', () => {
  it('has vectors of every proof kind', () => {
    for (const kind of PROOF_KINDS) {
      expect(proofCases.filter(c => c.kind === kind).length, kind).toBeGreaterThan(0)
    }
  })

  for (const c of proofCases) {
    it(`${c.name} verifies under its own context`, () => {
      expect(c.verify(c.ctx)).toBe(true)
    })

    it(`${c.name} fails with index + 1`, () => {
      expect(c.verify({ ...c.ctx, index: c.ctx.index + 1 })).toBe(false)
    })

    it(`${c.name} fails with a different ballotId`, () => {
      expect(c.verify({ ...c.ctx, ballotId: OTHER_BALLOT_ID })).toBe(false)
    })
  }

  it('verifies the Cyrillic election-ID vectors', () => {
    const cyrillic = proofCases.filter(c => !isAscii(c.ctx.electionId))
    for (const kind of PROOF_KINDS) {
      expect(cyrillic.filter(c => c.kind === kind).length, kind).toBeGreaterThan(0)
    }
    for (const c of cyrillic) {
      expect(c.verify(c.ctx), c.name).toBe(true)
    }
  })
})
