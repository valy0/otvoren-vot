import { describe, it, expect, beforeAll } from 'vitest'
import { initSodium, getSodium } from '../sodium'
import { encrypt, encryptWithRandomness, homomorphicSum, hexToBytes, type Ciphertext } from '../elgamal'
import { fiatShamir } from '../fiatShamir'
import {
  type BinaryProof,
  proveBinary,
  verifyBinary,
  proveSumOne,
  verifySumOne,
  proveCandidateSum,
  verifyCandidateSum,
  proveConsistency,
  verifyConsistency,
  type ProofContext,
} from '../proofs'

beforeAll(async () => {
  await initSodium()
})

function makeKeyPair() {
  const sodium = getSodium()
  const sk = sodium.crypto_core_ristretto255_scalar_random()
  const pk = sodium.crypto_scalarmult_ristretto255_base(sk)
  return { sk, pk }
}

const CTX: ProofContext = {
  electionId: 'election-2027-national-assembly',
  ballotId: 'Zm9yLXRoZS1leGFtcGxlLW9ubHktMzItYnl0ZXMtISE',
  index: 0,
}

function ctxAt(index: number): ProofContext {
  return { ...CTX, index }
}

describe('proveBinary + verifyBinary', () => {
  it('verifies a proof for m=0', () => {
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(0, pk)
    const proof = proveBinary(CTX, 0, randomness, pk, ciphertext)
    expect(verifyBinary(CTX, pk, ciphertext, proof)).toBe(true)
  })

  it('verifies a proof for m=1', () => {
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(1, pk)
    const proof = proveBinary(CTX, 1, randomness, pk, ciphertext)
    expect(verifyBinary(CTX, pk, ciphertext, proof)).toBe(true)
  })

  it('rejects a tampered proof (flipped bit in z0)', () => {
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(0, pk)
    const proof = proveBinary(CTX, 0, randomness, pk, ciphertext)

    // Flip the first byte of z0 to corrupt the response
    const tamperedZ0 = new Uint8Array(proof.z0)
    tamperedZ0[0] ^= 0xff
    const tampered = { ...proof, z0: tamperedZ0 }

    expect(verifyBinary(CTX, pk, ciphertext, tampered)).toBe(false)
  })

  it('rejects a tampered proof (flipped bit in e1)', () => {
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(1, pk)
    const proof = proveBinary(CTX, 1, randomness, pk, ciphertext)

    const tamperedE1 = new Uint8Array(proof.e1)
    tamperedE1[0] ^= 0x01
    const tampered = { ...proof, e1: tamperedE1 }

    expect(verifyBinary(CTX, pk, ciphertext, tampered)).toBe(false)
  })

  it('rejects when wrong ciphertext is paired with a valid proof', () => {
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(0, pk)
    const proof = proveBinary(CTX, 0, randomness, pk, ciphertext)

    // Use a different ciphertext with the same proof
    const { ciphertext: otherCt } = encrypt(1, pk)
    expect(verifyBinary(CTX, pk, otherCt, proof)).toBe(false)
  })
})

describe('party vector with blank vote slot', () => {
  it('encrypts party vector with numParties+1 length (extra blank vote slot)', () => {
    const { pk } = makeKeyPair()
    const numParties = 4
    const partyIndex = 2
    const partyVectorLen = numParties + 1  // +1 for blank vote slot

    const encResults = Array.from({ length: partyVectorLen }, (_, i) => {
      return encrypt(i === partyIndex ? 1 : 0, pk)
    })

    for (let i = 0; i < partyVectorLen; i++) {
      const bit = (i === partyIndex ? 1 : 0) as 0 | 1
      const proof = proveBinary(ctxAt(i), bit, encResults[i].randomness, pk, encResults[i].ciphertext)
      expect(verifyBinary(ctxAt(i), pk, encResults[i].ciphertext, proof)).toBe(true)
    }

    const cts = encResults.map(r => r.ciphertext)
    const sodium = getSodium()
    let rSum = encResults[0].randomness
    for (let i = 1; i < encResults.length; i++) {
      rSum = sodium.crypto_core_ristretto255_scalar_add(rSum, encResults[i].randomness)
    }
    const sumProof = proveSumOne(CTX, cts, rSum, pk)
    expect(verifySumOne(CTX, pk, cts, sumProof)).toBe(true)
  })

  it('selects blank vote slot (last element) when partyIndex equals numParties', () => {
    const { pk } = makeKeyPair()
    const numParties = 4
    const partyIndex = numParties  // blank vote = last slot
    const partyVectorLen = numParties + 1

    const encResults = Array.from({ length: partyVectorLen }, (_, i) => {
      return encrypt(i === partyIndex ? 1 : 0, pk)
    })

    const cts = encResults.map(r => r.ciphertext)
    const sodium = getSodium()
    let rSum = encResults[0].randomness
    for (let i = 1; i < encResults.length; i++) {
      rSum = sodium.crypto_core_ristretto255_scalar_add(rSum, encResults[i].randomness)
    }
    const sumProof = proveSumOne(CTX, cts, rSum, pk)
    expect(verifySumOne(CTX, pk, cts, sumProof)).toBe(true)
  })
})

describe('candidate vector encryption', () => {
  it('encrypts candidate preference as one-hot vector with virtual no-preference slot', () => {
    const { pk } = makeKeyPair()
    const numCandidates = 3
    const candidateIndex = 1
    const vectorLength = numCandidates + 1

    const encResults = Array.from({ length: vectorLength }, (_, i) => {
      return encrypt(i === candidateIndex ? 1 : 0, pk)
    })

    for (let i = 0; i < vectorLength; i++) {
      const bit = (i === candidateIndex ? 1 : 0) as 0 | 1
      const proof = proveBinary(ctxAt(i), bit, encResults[i].randomness, pk, encResults[i].ciphertext)
      expect(verifyBinary(ctxAt(i), pk, encResults[i].ciphertext, proof)).toBe(true)
    }

    const cts = encResults.map(r => r.ciphertext)
    const sodium = getSodium()
    let rSum = encResults[0].randomness
    for (let i = 1; i < encResults.length; i++) {
      rSum = sodium.crypto_core_ristretto255_scalar_add(rSum, encResults[i].randomness)
    }
    const sumProof = proveSumOne(CTX, cts, rSum, pk)
    expect(verifySumOne(CTX, pk, cts, sumProof)).toBe(true)
  })

  it('encrypts no-preference as last slot selected in candidate vector', () => {
    const { pk } = makeKeyPair()
    const numCandidates = 3
    const vectorLength = numCandidates + 1
    const activeIndex = vectorLength - 1

    const encResults = Array.from({ length: vectorLength }, (_, i) => {
      return encrypt(i === activeIndex ? 1 : 0, pk)
    })

    const cts = encResults.map(r => r.ciphertext)
    const sodium = getSodium()
    let rSum = encResults[0].randomness
    for (let i = 1; i < encResults.length; i++) {
      rSum = sodium.crypto_core_ristretto255_scalar_add(rSum, encResults[i].randomness)
    }
    const sumProof = proveSumOne(CTX, cts, rSum, pk)
    expect(verifySumOne(CTX, pk, cts, sumProof)).toBe(true)
  })
})

describe('proveSumOne + verifySumOne', () => {
  it('verifies a one-hot vector [0, 1, 0]', () => {
    const sodium = getSodium()
    const { pk } = makeKeyPair()

    const r0Res = encrypt(0, pk)
    const r1Res = encrypt(1, pk)
    const r2Res = encrypt(0, pk)

    const cts = [r0Res.ciphertext, r1Res.ciphertext, r2Res.ciphertext]

    // Sum all randomness scalars
    const rSum = sodium.crypto_core_ristretto255_scalar_add(
      sodium.crypto_core_ristretto255_scalar_add(r0Res.randomness, r1Res.randomness),
      r2Res.randomness,
    )

    const proof = proveSumOne(CTX, cts, rSum, pk)
    expect(verifySumOne(CTX, pk, cts, proof)).toBe(true)
  })

  it('verifies a single-element vector encrypting 1', () => {
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(1, pk)
    const proof = proveSumOne(CTX, [ciphertext], randomness, pk)
    expect(verifySumOne(CTX, pk, [ciphertext], proof)).toBe(true)
  })

  it('rejects an all-zeros vector (sum = 0, not 1)', () => {
    const sodium = getSodium()
    const { pk } = makeKeyPair()

    const r0 = encrypt(0, pk)
    const r1 = encrypt(0, pk)
    const cts = [r0.ciphertext, r1.ciphertext]

    // Use correct rSum for sum=0 ciphertexts
    const rSum = sodium.crypto_core_ristretto255_scalar_add(r0.randomness, r1.randomness)

    // Build a proof for the all-zero vector (but verifySumOne checks sum=1)
    const proof = proveSumOne(CTX, cts, rSum, pk)

    // The proof is for the aggregate of all-zeros, which encrypts 0, not 1.
    // Verification checks h^z == b + (aggC2 - g)*e. Since aggC2 = h^rSum (no g),
    // the equation won't hold with the Schnorr relation for rSum.
    expect(verifySumOne(CTX, pk, cts, proof)).toBe(false)
  })

  it('rejects a tampered proof (modified z)', () => {
    const sodium = getSodium()
    const { pk } = makeKeyPair()

    const r0 = encrypt(0, pk)
    const r1 = encrypt(1, pk)
    const cts = [r0.ciphertext, r1.ciphertext]
    const rSum = sodium.crypto_core_ristretto255_scalar_add(r0.randomness, r1.randomness)

    const proof = proveSumOne(CTX, cts, rSum, pk)

    const tamperedZ = new Uint8Array(proof.z)
    tamperedZ[0] ^= 0xff
    const tampered = { ...proof, z: tamperedZ }

    expect(verifySumOne(CTX, pk, cts, tampered)).toBe(false)
  })
})

describe('context binding', () => {
  it('a binary or sum proof fails under another index, ballot or election', () => {
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(1, pk)
    const ctx = ctxAt(4)
    const binary = proveBinary(ctx, 1, randomness, pk, ciphertext)
    const sum = proveSumOne(ctx, [ciphertext], randomness, pk)
    expect(verifyBinary(ctx, pk, ciphertext, binary)).toBe(true)
    expect(verifySumOne(ctx, pk, [ciphertext], sum)).toBe(true)

    const moved: ProofContext[] = [
      { ...ctx, index: ctx.index + 1 },
      { ...ctx, ballotId: 'other-ballot' },
      { ...ctx, electionId: 'other-election' },
      // Same concatenated bytes, different field boundary.
      { ...ctx, electionId: ctx.electionId + ctx.ballotId.slice(0, 1), ballotId: ctx.ballotId.slice(1) },
    ]
    for (const other of moved) {
      expect(verifyBinary(other, pk, ciphertext, binary)).toBe(false)
      expect(verifySumOne(other, pk, [ciphertext], sum)).toBe(false)
    }
  })
})

/** Encrypts `bits` and returns the ciphertexts, their aggregate and the randomness sum. */
function encryptVector(pk: Uint8Array, bits: (0 | 1)[]) {
  const sodium = getSodium()
  const encs = bits.map(b => encrypt(b, pk))
  const cts: Ciphertext[] = encs.map(e => e.ciphertext)
  const agg = homomorphicSum(cts)
  if (agg === null) throw new Error('empty vector')
  let rSum = encs[0].randomness
  for (let i = 1; i < encs.length; i++) {
    rSum = sodium.crypto_core_ristretto255_scalar_add(rSum, encs[i].randomness)
  }
  return { agg, rSum }
}

describe('proveCandidateSum + verifyCandidateSum', () => {
  it('verifies a candidate vector summing to 0 and to 1', () => {
    const { pk } = makeKeyPair()
    for (const [bits, sum] of [[[0, 0, 0], 0], [[0, 1, 0], 1]] as const) {
      const { agg, rSum } = encryptVector(pk, [...bits])
      const proof = proveCandidateSum(ctxAt(2), sum, rSum, pk, agg)
      expect(verifyCandidateSum(ctxAt(2), pk, agg, proof)).toBe(true)
      expect(verifyCandidateSum(ctxAt(3), pk, agg, proof)).toBe(false)
    }
  })

  it('rejects a vector summing to 2 claimed as 1', () => {
    const { pk } = makeKeyPair()
    const { agg, rSum } = encryptVector(pk, [1, 1, 0])
    const proof = proveCandidateSum(CTX, 1, rSum, pk, agg)
    expect(verifyCandidateSum(CTX, pk, agg, proof)).toBe(false)
  })

  it('does not verify as a binary proof (different domain)', () => {
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(1, pk)
    const proof = proveCandidateSum(CTX, 1, randomness, pk, ciphertext)
    expect(verifyCandidateSum(CTX, pk, ciphertext, proof)).toBe(true)
    expect(verifyBinary(CTX, pk, ciphertext, proof)).toBe(false)
  })
})

describe('proveConsistency + verifyConsistency', () => {
  // (party bit, candidate bits): the three valid combinations and their diff.
  const valid = [
    { party: 1, cands: [0, 1, 0], diff: 0 },
    { party: 1, cands: [0, 0, 0], diff: 1 },
    { party: 0, cands: [0, 0, 0], diff: 0 },
  ] as const

  for (const { party, cands, diff } of valid) {
    it(`verifies party=${party}, candidate sum=${cands.some(c => c === 1) ? 1 : 0}, diff=${diff}`, () => {
      const sodium = getSodium()
      const { pk } = makeKeyPair()
      const partyEnc = encrypt(party, pk)
      const { agg, rSum } = encryptVector(pk, [...cands])
      const rDiff = sodium.crypto_core_ristretto255_scalar_sub(partyEnc.randomness, rSum)
      const proof = proveConsistency(ctxAt(1), diff, rDiff, pk, partyEnc.ciphertext, agg)
      expect(verifyConsistency(ctxAt(1), pk, partyEnc.ciphertext, agg, proof)).toBe(true)
      expect(verifyConsistency(ctxAt(2), pk, partyEnc.ciphertext, agg, proof)).toBe(false)
    })
  }

  it('rejects a candidate selected in an unselected party (diff = −1 claimed as 0)', () => {
    const sodium = getSodium()
    const { pk } = makeKeyPair()
    const partyEnc = encrypt(0, pk)
    const { agg, rSum } = encryptVector(pk, [1, 0, 0])
    const rDiff = sodium.crypto_core_ristretto255_scalar_sub(partyEnc.randomness, rSum)
    const proof = proveConsistency(CTX, 0, rDiff, pk, partyEnc.ciphertext, agg)
    expect(verifyConsistency(CTX, pk, partyEnc.ciphertext, agg, proof)).toBe(false)
  })
})

describe('malformed input', () => {
  const ctx: ProofContext = {
    electionId: 'избори-2027-народно-събрание',
    ballotId: 'Zm9yLXRoZS1leGFtcGxlLW9ubHktMzItYnl0ZXMtISE',
    index: 0,
  }

  // ℓ, the order of the Ristretto255 group, little-endian.
  const GROUP_ORDER = hexToBytes('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010')

  /** Adds ℓ to a canonical scalar: the same value mod ℓ, encoded non-canonically. */
  function addGroupOrder(s: Uint8Array): Uint8Array {
    const out = new Uint8Array(32)
    let carry = 0
    for (let i = 0; i < 32; i++) {
      const v = s[i] + GROUP_ORDER[i] + carry
      out[i] = v & 0xff
      carry = v >> 8
    }
    return out
  }

  function validBinary() {
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(1, pk)
    const proof = proveBinary(ctx, 1, randomness, pk, ciphertext)
    expect(verifyBinary(ctx, pk, ciphertext, proof)).toBe(true)
    return { pk, ct: ciphertext, proof }
  }

  function expectFalseWithoutThrowing(verify: () => boolean) {
    let result: boolean | undefined
    expect(() => { result = verify() }).not.toThrow()
    expect(result).toBe(false)
  }

  it('verifyBinary returns false for an a1 of 31 bytes', () => {
    const { pk, ct, proof } = validBinary()
    expectFalseWithoutThrowing(() => verifyBinary(ctx, pk, ct, { ...proof, a1: proof.a1.slice(0, 31) }))
  })

  it('verifyBinary returns false for an a0 of 32 zero bytes', () => {
    const { pk, ct, proof } = validBinary()
    expectFalseWithoutThrowing(() => verifyBinary(ctx, pk, ct, { ...proof, a0: new Uint8Array(32) }))
  })

  it('verifyBinary returns false for a z0 equal to the group order', () => {
    const { pk, ct, proof } = validBinary()
    expectFalseWithoutThrowing(() => verifyBinary(ctx, pk, ct, { ...proof, z0: GROUP_ORDER.slice() }))
  })

  it('verifyBinary returns false for an e1 of all 0xff bytes', () => {
    const { pk, ct, proof } = validBinary()
    expectFalseWithoutThrowing(() => verifyBinary(ctx, pk, ct, { ...proof, e1: new Uint8Array(32).fill(0xff) }))
  })

  it('verifyBinary returns false for a non-canonical alias (+ℓ) of e1 or z0', () => {
    const { pk, ct, proof } = validBinary()
    expectFalseWithoutThrowing(() => verifyBinary(ctx, pk, ct, { ...proof, e1: addGroupOrder(proof.e1) }))
    expectFalseWithoutThrowing(() => verifyBinary(ctx, pk, ct, { ...proof, z0: addGroupOrder(proof.z0) }))
  })

  it('verifyBinary returns false for an empty ID or an index outside uint32', () => {
    const { pk, ct, proof } = validBinary()
    expectFalseWithoutThrowing(() => verifyBinary({ ...ctx, electionId: '' }, pk, ct, proof))
    expectFalseWithoutThrowing(() => verifyBinary({ ...ctx, ballotId: '' }, pk, ct, proof))
    expectFalseWithoutThrowing(() => verifyBinary({ ...ctx, index: -1 }, pk, ct, proof))
    expectFalseWithoutThrowing(() => verifyBinary({ ...ctx, index: 2 ** 32 }, pk, ct, proof))
    expectFalseWithoutThrowing(() => verifyBinary({ ...ctx, index: 0.5 }, pk, ct, proof))
  })

  it('verifySumOne returns false for an empty ciphertext vector', () => {
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(1, pk)
    const proof = proveSumOne(ctx, [ciphertext], randomness, pk)
    expect(verifySumOne(ctx, pk, [ciphertext], proof)).toBe(true)
    expectFalseWithoutThrowing(() => verifySumOne(ctx, pk, [], proof))
  })

  it('verifyCandidateSum and verifyConsistency return false for a 31-byte field or a zero point', () => {
    const { pk, ct, proof } = validBinary()
    const short = ct.c2.slice(0, 31)
    expectFalseWithoutThrowing(() => verifyCandidateSum(ctx, pk, { ...ct, c2: short }, proof))
    expectFalseWithoutThrowing(() => verifyCandidateSum(ctx, pk, ct, { ...proof, z1: proof.z1.slice(0, 31) }))
    expectFalseWithoutThrowing(() => verifyConsistency(ctx, pk, { ...ct, c1: short }, ct, proof))
    expectFalseWithoutThrowing(() => verifyConsistency(ctx, pk, ct, { ...ct, c1: new Uint8Array(32) }, proof))
    expectFalseWithoutThrowing(() => verifyConsistency(ctx, new Uint8Array(32), ct, ct, proof))
  })

  it('provers throw on an empty ID or an index outside uint32', () => {
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(0, pk)
    const bad: ProofContext[] = [
      { ...ctx, electionId: '' },
      { ...ctx, ballotId: '' },
      { ...ctx, index: -1 },
      { ...ctx, index: 2 ** 32 },
      { ...ctx, index: 1.5 },
      { ...ctx, index: Number.NaN },
    ]
    for (const c of bad) {
      expect(() => proveBinary(c, 0, randomness, pk, ciphertext)).toThrow()
      expect(() => proveSumOne(c, [ciphertext], randomness, pk)).toThrow()
    }
    expect(() => proveBinary({ ...ctx, index: 2 ** 32 - 1 }, 0, randomness, pk, ciphertext)).not.toThrow()
  })
})

// Go's ScalarMult returns the identity for a zero scalar or an identity point
// and carries on; libsodium refuses such a result. A verifier that called
// libsodium directly would reject these sound proofs, which Go accepts. Every
// wire field below is still a non-identity point and a canonical scalar.
describe('identity intermediates (accepted, as in Go)', () => {
  const ZERO = new Uint8Array(32)
  const ONE = new Uint8Array(32)
  ONE[0] = 1
  const BINARY_DOMAIN = 'otvoren-vot.ballot-binary-proof'
  const CONSISTENCY_DOMAIN = 'otvoren-vot.candidate-consistency-proof'

  const isZero = (b: Uint8Array) => b.every(x => x === 0)

  // Test-only scalar-mults that return the identity encoding where libsodium throws.
  function mulBaseOrIdentity(s: Uint8Array): Uint8Array {
    return isZero(s) ? new Uint8Array(32) : getSodium().crypto_scalarmult_ristretto255_base(s)
  }
  function mulOrIdentity(s: Uint8Array, point: Uint8Array): Uint8Array {
    return isZero(s) || isZero(point) ? new Uint8Array(32) : getSodium().crypto_scalarmult_ristretto255(s, point)
  }

  /** The context fields of docs/protocol/fiat-shamir.md, "Ballot-Proof Context". */
  function contextFields(ctx: ProofContext): Uint8Array[] {
    const index = new Uint8Array(4)
    new DataView(index.buffer).setUint32(0, ctx.index, false)
    const utf8 = new TextEncoder()
    return [utf8.encode(ctx.electionId), utf8.encode(ctx.ballotId), index]
  }

  /**
   * Test-only: the disjunctive proof built by hand, so that the simulated
   * branch's challenge `simE` and response `simZ` can be chosen. The provers
   * draw them at random and cannot multiply by a zero scalar or the identity.
   * Branch m is real (witness r); branch 1 − m is simulated.
   */
  function handBuiltDisjunctive(
    domain: string, ctx: ProofContext, pk: Uint8Array, ct: Ciphertext,
    m: 0 | 1, r: Uint8Array, simE: Uint8Array, simZ: Uint8Array,
  ): BinaryProof {
    const sodium = getSodium()
    const c2MinusG = sodium.crypto_core_ristretto255_sub(ct.c2, mulBaseOrIdentity(ONE))
    // The simulated branch's "c2" is c2 for branch 0 and c2 − g for branch 1.
    const simC2 = m === 0 ? c2MinusG : ct.c2
    const aSim = sodium.crypto_core_ristretto255_sub(mulBaseOrIdentity(simZ), mulOrIdentity(simE, ct.c1))
    const bSim = sodium.crypto_core_ristretto255_sub(mulOrIdentity(simZ, pk), mulOrIdentity(simE, simC2))
    const k = sodium.crypto_core_ristretto255_scalar_random()
    const aReal = mulBaseOrIdentity(k)
    const bReal = mulOrIdentity(k, pk)
    const [a0, b0, a1, b1] = m === 0 ? [aReal, bReal, aSim, bSim] : [aSim, bSim, aReal, bReal]
    const e = fiatShamir(domain, ...contextFields(ctx), pk, ct.c1, ct.c2, a0, b0, a1, b1)
    const eReal = sodium.crypto_core_ristretto255_scalar_sub(e, simE)
    const zReal = sodium.crypto_core_ristretto255_scalar_add(k, sodium.crypto_core_ristretto255_scalar_mul(eReal, r))
    return m === 0
      ? { a0, b0, a1, b1, e0: eReal, e1: simE, z0: zReal, z1: simZ }
      : { a0, b0, a1, b1, e0: simE, e1: eReal, z0: simZ, z1: zReal }
  }

  const randomScalar = () => getSodium().crypto_core_ristretto255_scalar_random()

  it('verifyBinary accepts a proof whose simulated challenge e0 is 0', () => {
    const { pk } = makeKeyPair()
    const r = randomScalar()
    const ct = encryptWithRandomness(1, r, pk)
    const proof = handBuiltDisjunctive(BINARY_DOMAIN, CTX, pk, ct, 1, r, ZERO, randomScalar())
    expect(isZero(proof.e0)).toBe(true)
    expect(verifyBinary(CTX, pk, ct, proof)).toBe(true)
  })

  it('verifyBinary accepts a proof whose simulated challenge e1 is 0', () => {
    const { pk } = makeKeyPair()
    const r = randomScalar()
    const ct = encryptWithRandomness(0, r, pk)
    const proof = handBuiltDisjunctive(BINARY_DOMAIN, CTX, pk, ct, 0, r, ZERO, randomScalar())
    expect(isZero(proof.e1)).toBe(true)
    expect(verifyBinary(CTX, pk, ct, proof)).toBe(true)
  })

  it('verifyBinary accepts a proof whose simulated response z0 is 0', () => {
    const { pk } = makeKeyPair()
    const r = randomScalar()
    const ct = encryptWithRandomness(1, r, pk)
    const proof = handBuiltDisjunctive(BINARY_DOMAIN, CTX, pk, ct, 1, r, randomScalar(), ZERO)
    expect(isZero(proof.z0)).toBe(true)
    expect(verifyBinary(CTX, pk, ct, proof)).toBe(true)
  })

  it('verifySumOne accepts a vector whose randomness sums to 0 (aggregate c1 is the identity)', () => {
    const sodium = getSodium()
    const { pk } = makeKeyPair()
    const r1 = randomScalar()
    const r2 = randomScalar()
    const r3 = sodium.crypto_core_ristretto255_scalar_negate(sodium.crypto_core_ristretto255_scalar_add(r1, r2))
    const cts = [encryptWithRandomness(0, r1, pk), encryptWithRandomness(1, r2, pk), encryptWithRandomness(0, r3, pk)]
    const rSum = sodium.crypto_core_ristretto255_scalar_add(sodium.crypto_core_ristretto255_scalar_add(r1, r2), r3)
    expect(isZero(rSum)).toBe(true)
    expect(isZero(homomorphicSum(cts)?.c1 ?? ONE)).toBe(true)

    const proof = proveSumOne(CTX, cts, rSum, pk)
    expect(verifySumOne(CTX, pk, cts, proof)).toBe(true)
  })

  for (const { party, cands, diff } of [
    { party: 1, cands: [0, 1, 0], diff: 0 },
    { party: 1, cands: [0, 0, 0], diff: 1 },
  ] as const) {
    it(`verifyConsistency accepts r_party = R_cand (difference c1 is the identity), diff=${diff}`, () => {
      const sodium = getSodium()
      const { pk } = makeKeyPair()
      const rs = cands.map(() => randomScalar())
      const candCts = cands.map((bit, i) => encryptWithRandomness(bit, rs[i], pk))
      const agg = homomorphicSum(candCts)
      if (agg === null) throw new Error('empty vector')
      const rCand = rs.reduce((acc, r) => sodium.crypto_core_ristretto255_scalar_add(acc, r))
      const partyCt = encryptWithRandomness(party, rCand, pk)  // r_party = R_cand
      const diffCt = {
        c1: sodium.crypto_core_ristretto255_sub(partyCt.c1, agg.c1),
        c2: sodium.crypto_core_ristretto255_sub(partyCt.c2, agg.c2),
      }
      expect(isZero(diffCt.c1)).toBe(true)

      // rDiff = r_party − R_cand = 0. proveConsistency cannot build this one: its
      // simulated branch multiplies by the identity c1, which libsodium refuses.
      const proof = handBuiltDisjunctive(CONSISTENCY_DOMAIN, CTX, pk, diffCt, diff, ZERO, randomScalar(), randomScalar())
      expect(verifyConsistency(CTX, pk, partyCt, agg, proof)).toBe(true)
    })
  }
})
