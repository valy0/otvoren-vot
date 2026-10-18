import { describe, it, expect, beforeAll, vi } from 'vitest'
import { initSodium, getSodium } from '../sodium'
import { bytesToHex, deserializeCiphertext, hexToBytes, type Ciphertext } from '../elgamal'
import { verifyBinary, verifySumOne } from '../proofs'
import type { BinaryProof, ProofContext, SumOneProof } from '../proofs'
import { buildBallot } from '../ballotBuilder'
import type { WorkerRequest, WorkerResponse } from '../worker'

const ELECTION_ID = 'избори-2027-народно-събрание'
const NUM_PARTIES = 3
const NUM_CANDIDATES = 2

beforeAll(async () => {
  await initSodium()
})

function binaryFromHex(p: Record<'a0' | 'b0' | 'a1' | 'b1' | 'e0' | 'e1' | 'z0' | 'z1', string>): BinaryProof {
  return {
    a0: hexToBytes(p.a0), b0: hexToBytes(p.b0), a1: hexToBytes(p.a1), b1: hexToBytes(p.b1),
    e0: hexToBytes(p.e0), e1: hexToBytes(p.e1), z0: hexToBytes(p.z0), z1: hexToBytes(p.z1),
  }
}

function sumOneFromHex(p: { a: string; b: string; z: string }): SumOneProof {
  return { a: hexToBytes(p.a), b: hexToBytes(p.b), z: hexToBytes(p.z) }
}

function newKeyPair() {
  const sodium = getSodium()
  const sk = sodium.crypto_core_ristretto255_scalar_random()
  return { sk, pk: sodium.crypto_scalarmult_ristretto255_base(sk) }
}

type EncryptResult = Extract<WorkerResponse, { type: 'encrypt-result' }>

function build(pk: Uint8Array, overrides: Partial<WorkerRequest> = {}): EncryptResult {
  const req: WorkerRequest = {
    type: 'encrypt-ballot',
    electionId: ELECTION_ID,
    electionPubKey: bytesToHex(pk),
    partyIndex: 1,
    numParties: NUM_PARTIES,
    candidateIndex: 0,
    numCandidates: NUM_CANDIDATES,
    ...overrides,
  }
  const res = buildBallot(req, getSodium())
  if (res.type !== 'encrypt-result') throw new Error('expected encrypt-result')
  return res
}

/** c2 − sk·c1 == g: the ciphertext encrypts 1. */
function encryptsOne(sk: Uint8Array, ct: Ciphertext): boolean {
  const sodium = getSodium()
  const one = new Uint8Array(32)
  one[0] = 1
  const gm = sodium.crypto_core_ristretto255_sub(ct.c2, sodium.crypto_scalarmult_ristretto255(sk, ct.c1))
  return bytesToHex(gm) === bytesToHex(sodium.crypto_scalarmult_ristretto255_base(one))
}

describe('buildBallot', () => {
  it('binds every proof to (election, ballot, index)', () => {
    const { pk } = newKeyPair()
    const res = build(pk)
    const ctx = (index: number): ProofContext => ({ electionId: ELECTION_ID, ballotId: res.ballotId, index })

    // Party block: NUM_PARTIES + 1 slots (last = blank), slot i -> index i, sum -> 0.
    const partyCts = res.encryptedBallot.party_vector.map(deserializeCiphertext)
    expect(partyCts).toHaveLength(NUM_PARTIES + 1)
    expect(res.zkProofs.binary_party).toHaveLength(NUM_PARTIES + 1)
    res.zkProofs.binary_party.forEach((raw, i) => {
      expect(verifyBinary(ctx(i), pk, partyCts[i], binaryFromHex(raw))).toBe(true)
    })
    const partySum = sumOneFromHex(res.zkProofs.sum_one)
    expect(verifySumOne(ctx(0), pk, partyCts, partySum)).toBe(true)

    // Legacy candidate block: slot j -> numParties + 1 + j, sum-one -> 1.
    const candCts = res.encryptedBallot.candidate_vectors[0].map(deserializeCiphertext)
    expect(candCts).toHaveLength(NUM_CANDIDATES + 1)
    const candProofs = res.zkProofs.binary_candidate
    if (!candProofs || !res.zkProofs.sum_one_candidate) throw new Error('expected candidate proofs')
    candProofs.forEach((raw, j) => {
      expect(verifyBinary(ctx(NUM_PARTIES + 1 + j), pk, candCts[j], binaryFromHex(raw))).toBe(true)
    })
    const candSum = sumOneFromHex(res.zkProofs.sum_one_candidate)
    expect(verifySumOne(ctx(1), pk, candCts, candSum)).toBe(true)

    // Negatives: each proof fails at a neighbouring index or under another ballot.
    const p0 = binaryFromHex(res.zkProofs.binary_party[0])
    expect(verifyBinary(ctx(1), pk, partyCts[0], p0)).toBe(false)
    expect(verifySumOne(ctx(1), pk, partyCts, partySum)).toBe(false)
    expect(verifySumOne(ctx(0), pk, candCts, candSum)).toBe(false)
    const c0 = binaryFromHex(candProofs[0])
    const otherBallot: ProofContext = { ...ctx(NUM_PARTIES + 1), ballotId: build(pk).ballotId }
    expect(otherBallot.ballotId).not.toBe(res.ballotId)
    expect(verifyBinary(otherBallot, pk, candCts[0], c0)).toBe(false)
  })

  for (const numCandidates of [undefined, 0]) {
    it(`emits no candidate block for numCandidates=${String(numCandidates)}`, () => {
      const { pk } = newKeyPair()
      const res = build(pk, { numCandidates, candidateIndex: undefined })
      expect(res.encryptedBallot.candidate_vectors).toEqual([])
      expect(res.zkProofs.binary_candidate).toBeUndefined()
      expect(res.zkProofs.sum_one_candidate).toBeUndefined()

      const ctx = (index: number): ProofContext => ({ electionId: ELECTION_ID, ballotId: res.ballotId, index })
      const partyCts = res.encryptedBallot.party_vector.map(deserializeCiphertext)
      expect(partyCts).toHaveLength(NUM_PARTIES + 1)
      res.zkProofs.binary_party.forEach((raw, i) => {
        expect(verifyBinary(ctx(i), pk, partyCts[i], binaryFromHex(raw))).toBe(true)
      })
      expect(verifySumOne(ctx(0), pk, partyCts, sumOneFromHex(res.zkProofs.sum_one))).toBe(true)
    })
  }

  it('rejects an empty election id before drawing any randomness', () => {
    const sodium = getSodium()
    const { pk } = newKeyPair()
    const randombytes = vi.spyOn(sodium, 'randombytes_buf')
    const scalarRandom = vi.spyOn(sodium, 'crypto_core_ristretto255_scalar_random')
    try {
      expect(() => build(pk, { electionId: '' })).toThrow(/election id/)
      expect(randombytes).not.toHaveBeenCalled()
      expect(scalarRandom).not.toHaveBeenCalled()
    } finally {
      randombytes.mockRestore()
      scalarRandom.mockRestore()
    }
  })

  describe('rejects invalid choices before drawing any randomness', () => {
    const cases: Array<[string, Partial<WorkerRequest>, RegExp]> = [
      ['candidateIndex = numCandidates', { candidateIndex: NUM_CANDIDATES }, /candidateIndex/],
      ['candidateIndex = numCandidates + 1', { candidateIndex: NUM_CANDIDATES + 1 }, /candidateIndex/],
      ['candidateIndex = -2', { candidateIndex: -2 }, /candidateIndex/],
      ['candidateIndex = 0.5', { candidateIndex: 0.5 }, /candidateIndex/],
      ['candidateIndex = NaN', { candidateIndex: NaN }, /candidateIndex/],
      ['partyIndex = -1', { partyIndex: -1 }, /partyIndex/],
      ['partyIndex = numParties + 1', { partyIndex: NUM_PARTIES + 1 }, /partyIndex/],
      ['partyIndex = 0.5', { partyIndex: 0.5 }, /partyIndex/],
      ['partyIndex = NaN', { partyIndex: NaN }, /partyIndex/],
      ['numParties = 0', { numParties: 0, partyIndex: 0 }, /numParties/],
      ['numParties = 1.5', { numParties: 1.5, partyIndex: 0 }, /numParties/],
      ['numCandidates = -1', { numCandidates: -1 }, /numCandidates/],
      ['numCandidates = 1.5', { numCandidates: 1.5 }, /numCandidates/],
    ]
    for (const [name, overrides, message] of cases) {
      it(name, () => {
        const sodium = getSodium()
        const { pk } = newKeyPair()
        const randombytes = vi.spyOn(sodium, 'randombytes_buf')
        const scalarRandom = vi.spyOn(sodium, 'crypto_core_ristretto255_scalar_random')
        try {
          expect(() => build(pk, overrides)).toThrow(message)
          expect(randombytes).not.toHaveBeenCalled()
          expect(scalarRandom).not.toHaveBeenCalled()
        } finally {
          randombytes.mockRestore()
          scalarRandom.mockRestore()
        }
      })
    }

    it('still accepts every choice the UI can send', () => {
      const { pk } = newKeyPair()
      // blank vote, party without candidates, no preference, last candidate
      expect(() => build(pk, { partyIndex: NUM_PARTIES, candidateIndex: -1, numCandidates: 0 })).not.toThrow()
      expect(() => build(pk, { partyIndex: 0, candidateIndex: -1, numCandidates: 0 })).not.toThrow()
      expect(() => build(pk, { candidateIndex: -1 })).not.toThrow()
      expect(() => build(pk, { candidateIndex: NUM_CANDIDATES - 1 })).not.toThrow()
    })
  })

  it('selects the last candidate slot for candidateIndex = -1 (no preference)', () => {
    const { sk, pk } = newKeyPair()
    const res = build(pk, { candidateIndex: -1 })
    const ctx = (index: number): ProofContext => ({ electionId: ELECTION_ID, ballotId: res.ballotId, index })

    const candCts = res.encryptedBallot.candidate_vectors[0].map(deserializeCiphertext)
    expect(candCts).toHaveLength(NUM_CANDIDATES + 1)
    expect(candCts.map(ct => encryptsOne(sk, ct))).toEqual([false, false, true])
    const candProofs = res.zkProofs.binary_candidate
    if (!candProofs || !res.zkProofs.sum_one_candidate) throw new Error('expected candidate proofs')
    candProofs.forEach((raw, j) => {
      expect(verifyBinary(ctx(NUM_PARTIES + 1 + j), pk, candCts[j], binaryFromHex(raw))).toBe(true)
    })
    expect(verifySumOne(ctx(1), pk, candCts, sumOneFromHex(res.zkProofs.sum_one_candidate))).toBe(true)
  })
})
