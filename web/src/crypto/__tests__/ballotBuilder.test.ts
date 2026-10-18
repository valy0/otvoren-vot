import { describe, it, expect, beforeAll } from 'vitest'
import { initSodium, getSodium } from '../sodium'
import { bytesToHex, deserializeCiphertext, hexToBytes } from '../elgamal'
import { verifyBinary, verifySumOne } from '../proofs'
import type { BinaryProof, ProofContext, SumOneProof } from '../proofs'
import { buildBallot } from '../ballotBuilder'
import type { WorkerRequest } from '../worker'

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

describe('buildBallot', () => {
  it('binds every proof to (election, ballot, index)', () => {
    const sodium = getSodium()
    const pk = sodium.crypto_scalarmult_ristretto255_base(sodium.crypto_core_ristretto255_scalar_random())
    const req: WorkerRequest = {
      type: 'encrypt-ballot',
      electionId: ELECTION_ID,
      electionPubKey: bytesToHex(pk),
      partyIndex: 1,
      numParties: NUM_PARTIES,
      candidateIndex: 0,
      numCandidates: NUM_CANDIDATES,
    }

    const res = buildBallot(req, sodium)
    if (res.type !== 'encrypt-result') throw new Error('expected encrypt-result')
    const ctx = (index: number): ProofContext => ({ electionId: ELECTION_ID, ballotId: res.ballotId, index })

    // Party block: NUM_PARTIES + 1 slots (last = blank), slot i -> index i, sum -> 0.
    const partyCts = res.encryptedBallot.party_vector.map(deserializeCiphertext)
    expect(partyCts).toHaveLength(NUM_PARTIES + 1)
    expect(res.zkProofs.binary_party).toHaveLength(NUM_PARTIES + 1)
    res.zkProofs.binary_party.forEach((raw, i) => {
      expect(verifyBinary(ctx(i), pk, partyCts[i], binaryFromHex(raw))).toBe(true)
    })
    expect(verifySumOne(ctx(0), pk, partyCts, sumOneFromHex(res.zkProofs.sum_one))).toBe(true)

    // Legacy candidate block: slot j -> numParties + 1 + j, sum-one -> 1.
    const candCts = res.encryptedBallot.candidate_vectors[0].map(deserializeCiphertext)
    expect(candCts).toHaveLength(NUM_CANDIDATES + 1)
    const candProofs = res.zkProofs.binary_candidate
    if (!candProofs || !res.zkProofs.sum_one_candidate) throw new Error('expected candidate proofs')
    candProofs.forEach((raw, j) => {
      expect(verifyBinary(ctx(NUM_PARTIES + 1 + j), pk, candCts[j], binaryFromHex(raw))).toBe(true)
    })
    expect(verifySumOne(ctx(1), pk, candCts, sumOneFromHex(res.zkProofs.sum_one_candidate))).toBe(true)

    // Negative: a party-slot proof must not verify at a different index.
    const p0 = binaryFromHex(res.zkProofs.binary_party[0])
    expect(verifyBinary(ctx(1), pk, partyCts[0], p0)).toBe(false)
  })
})
