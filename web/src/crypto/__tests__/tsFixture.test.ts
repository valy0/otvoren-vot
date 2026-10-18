// Builds proofs with the browser's TypeScript provers, verifies them in TS and,
// when UPDATE_TS_FIXTURE=1, writes them to crypto/vectors/testdata/ts_proofs.json
// for Go to verify (crypto/vectors/ts_proofs_test.go). The schema is that of the
// proof sections of vectors.json; every binary value is lowercase hex.
import { writeFileSync } from 'node:fs'
import { describe, it, expect, beforeAll } from 'vitest'
import { initSodium, getSodium } from '../sodium'
import { encryptWithRandomness, homomorphicSum, bytesToHex, type Ciphertext } from '../elgamal'
import {
  proveBinary, verifyBinary,
  proveSumOne, verifySumOne,
  proveCandidateSum, verifyCandidateSum,
  proveConsistency, verifyConsistency,
  type BinaryProof, type ProofContext, type SumOneProof,
} from '../proofs'
import { BINARY_DOMAIN, ZERO, handBuiltDisjunctive, isZero, randomScalar, zeroRandomnessSumOne } from './identityEdges'

beforeAll(async () => {
  await initSodium()
})

const ASCII_ELECTION = 'election-2027-national-assembly'
const CYRILLIC_ELECTION = 'избори-2027-народно-събрание'

interface ContextJson { election_id: string; ballot_id: string; index: number }
interface CiphertextJson { c1_hex: string; c2_hex: string }
interface BinaryProofJson {
  a0_hex: string; b0_hex: string; a1_hex: string; b1_hex: string
  e0_hex: string; e1_hex: string; z0_hex: string; z1_hex: string
}

const ctJson = (ct: Ciphertext): CiphertextJson => ({ c1_hex: bytesToHex(ct.c1), c2_hex: bytesToHex(ct.c2) })
const ctxJson = (c: ProofContext): ContextJson => ({ election_id: c.electionId, ballot_id: c.ballotId, index: c.index })
const binaryProofJson = (p: BinaryProof): BinaryProofJson => ({
  a0_hex: bytesToHex(p.a0), b0_hex: bytesToHex(p.b0), a1_hex: bytesToHex(p.a1), b1_hex: bytesToHex(p.b1),
  e0_hex: bytesToHex(p.e0), e1_hex: bytesToHex(p.e1), z0_hex: bytesToHex(p.z0), z1_hex: bytesToHex(p.z1),
})
const sumOneProofJson = (p: SumOneProof) => ({ a_hex: bytesToHex(p.a), b_hex: bytesToHex(p.b), z_hex: bytesToHex(p.z) })

/** A 43-character unpadded base64url ballot id (32 random bytes). */
function newBallotId(): string {
  const raw = getSodium().randombytes_buf(32)
  return btoa(String.fromCharCode(...raw)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const sub = (a: Uint8Array, b: Uint8Array) => getSodium().crypto_core_ristretto255_scalar_sub(a, b)
const add = (a: Uint8Array, b: Uint8Array) => getSodium().crypto_core_ristretto255_scalar_add(a, b)

/** Encrypts `bits`; returns the aggregate ciphertext, the ciphertexts and the randomness sum. */
function encryptVector(pk: Uint8Array, bits: (0 | 1)[]) {
  const rs = bits.map(() => randomScalar())
  const cts = bits.map((b, i) => encryptWithRandomness(b, rs[i], pk))
  const agg = homomorphicSum(cts)
  if (agg === null) throw new Error('empty vector')
  return { cts, agg, rSum: rs.reduce(add) }
}

function buildFixture() {
  const sk = randomScalar()
  const pk = getSodium().crypto_scalarmult_ristretto255_base(sk)
  const public_key_hex = bytesToHex(pk)
  const ctxFor = (electionId: string, index: number): ProofContext => ({ electionId, ballotId: newBallotId(), index })

  const binary_proof: unknown[] = []
  const sum_one_proof: unknown[] = []
  const candidate_sum_proof: unknown[] = []
  const consistency_proof: unknown[] = []

  const addBinary = (ctx: ProofContext, message: 0 | 1, ct: Ciphertext, proof: BinaryProof) => {
    expect(verifyBinary(ctx, pk, ct, proof)).toBe(true)
    expect(verifyBinary({ ...ctx, index: ctx.index + 1 }, pk, ct, proof)).toBe(false)
    binary_proof.push({
      context: ctxJson(ctx), public_key_hex, message,
      ciphertext_c1_hex: bytesToHex(ct.c1), ciphertext_c2_hex: bytesToHex(ct.c2),
      proof: binaryProofJson(proof),
    })
  }
  // `contextBound` is false only for the zero-randomness edge: the aggregate is
  // then exactly (identity, g), both verification equations lose their dependence
  // on the challenge, and the proof verifies under any context. That is a property
  // of the statement, not of the prover; Go behaves the same.
  const addSumOne = (ctx: ProofContext, cts: Ciphertext[], proof: SumOneProof, contextBound = true) => {
    expect(verifySumOne(ctx, pk, cts, proof)).toBe(true)
    expect(verifySumOne({ ...ctx, index: ctx.index + 1 }, pk, cts, proof)).toBe(!contextBound)
    sum_one_proof.push({ context: ctxJson(ctx), public_key_hex, ciphertexts: cts.map(ctJson), proof: sumOneProofJson(proof) })
  }

  for (const election of [ASCII_ELECTION, CYRILLIC_ELECTION]) {
    // Binary proofs: slot i uses index i (ballot-proofs.md section 8.4).
    ;([0, 1] as const).forEach((m, i) => {
      const ctx = ctxFor(election, i)
      const r = randomScalar()
      const ct = encryptWithRandomness(m, r, pk)
      addBinary(ctx, m, ct, proveBinary(ctx, m, r, pk, ct))
    })

    // Sum-one over 3 slots: index 0.
    {
      const ctx = ctxFor(election, 0)
      const { cts, rSum } = encryptVector(pk, [0, 1, 0])
      addSumOne(ctx, cts, proveSumOne(ctx, cts, rSum, pk))
    }

    // Candidate-sum for party p: index p.
    ;([0, 1] as const).forEach(sum => {
      const ctx = ctxFor(election, sum + 2)
      const { agg, rSum } = encryptVector(pk, sum === 1 ? [0, 1, 0] : [0, 0, 0])
      const proof = proveCandidateSum(ctx, sum, rSum, pk, agg)
      expect(verifyCandidateSum(ctx, pk, agg, proof)).toBe(true)
      expect(verifyCandidateSum({ ...ctx, index: ctx.index + 1 }, pk, agg, proof)).toBe(false)
      candidate_sum_proof.push({
        context: ctxJson(ctx), public_key_hex, agg_c1_hex: bytesToHex(agg.c1), agg_c2_hex: bytesToHex(agg.c2),
        sum, proof: binaryProofJson(proof),
      })
    })

    // Consistency for party p: diff = party bit - candidate sum, in {0, 1}.
    ;([
      { party: 0, cands: [0, 0, 0], diff: 0 },
      { party: 1, cands: [0, 0, 0], diff: 1 },
      { party: 1, cands: [0, 1, 0], diff: 0 },
    ] as const).forEach(({ party, cands, diff }, p) => {
      const ctx = ctxFor(election, p)
      const rParty = randomScalar()
      const partyCt = encryptWithRandomness(party, rParty, pk)
      const { agg, rSum } = encryptVector(pk, [...cands])
      const proof = proveConsistency(ctx, diff, sub(rParty, rSum), pk, partyCt, agg)
      expect(verifyConsistency(ctx, pk, partyCt, agg, proof)).toBe(true)
      expect(verifyConsistency({ ...ctx, index: ctx.index + 1 }, pk, partyCt, agg, proof)).toBe(false)
      consistency_proof.push({
        context: ctxJson(ctx), public_key_hex, party_ciphertext: ctJson(partyCt), cand_sum_ciphertext: ctJson(agg),
        diff, proof: binaryProofJson(proof),
      })
    })
  }

  // Edge (a): a binary proof whose simulated challenge e0 is 0.
  {
    const ctx = ctxFor(ASCII_ELECTION, 2)
    const r = randomScalar()
    const ct = encryptWithRandomness(1, r, pk)
    const proof = handBuiltDisjunctive(BINARY_DOMAIN, ctx, pk, ct, 1, r, ZERO, randomScalar())
    expect(isZero(proof.e0)).toBe(true)
    addBinary(ctx, 1, ct, proof)
  }

  // Edge (b): a sum-one proof over 3 ciphertexts whose randomness sums to 0 mod l.
  {
    const ctx = ctxFor(CYRILLIC_ELECTION, 0)
    const { cts, proof } = zeroRandomnessSumOne(ctx, pk)
    addSumOne(ctx, cts, proof, false)
  }

  return { binary_proof, sum_one_proof, candidate_sum_proof, consistency_proof }
}

describe('browser-generated proof fixture', () => {
  it('builds and verifies one proof of each kind for every message value', () => {
    const fixture = buildFixture()
    expect(fixture.binary_proof.length).toBe(5)
    expect(fixture.sum_one_proof.length).toBe(3)
    expect(fixture.candidate_sum_proof.length).toBe(4)
    expect(fixture.consistency_proof.length).toBe(6)

    if (process.env.UPDATE_TS_FIXTURE === '1') {
      const url = new URL('../../../../crypto/vectors/testdata/ts_proofs.json', import.meta.url)
      writeFileSync(url, JSON.stringify(fixture, null, 2) + '\n')
    }
  })
})
