import { describe, it, expect, beforeAll } from 'vitest'
import { initSodium, getSodium } from '../sodium'
import { encrypt } from '../elgamal'
import { proveBinary, verifyBinary, proveSumOne, verifySumOne } from '../proofs'

beforeAll(async () => {
  await initSodium()
})

function makeKeyPair() {
  const sodium = getSodium()
  const sk = sodium.crypto_core_ristretto255_scalar_random()
  const pk = sodium.crypto_scalarmult_ristretto255_base(sk)
  return { sk, pk }
}

describe('proveBinary + verifyBinary', () => {
  it('verifies a proof for m=0', () => {
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(0, pk)
    const proof = proveBinary(0, randomness, pk, ciphertext)
    expect(verifyBinary(pk, ciphertext, proof)).toBe(true)
  })

  it('verifies a proof for m=1', () => {
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(1, pk)
    const proof = proveBinary(1, randomness, pk, ciphertext)
    expect(verifyBinary(pk, ciphertext, proof)).toBe(true)
  })

  it('rejects a tampered proof (flipped bit in z0)', () => {
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(0, pk)
    const proof = proveBinary(0, randomness, pk, ciphertext)

    // Flip the first byte of z0 to corrupt the response
    const tamperedZ0 = new Uint8Array(proof.z0)
    tamperedZ0[0] ^= 0xff
    const tampered = { ...proof, z0: tamperedZ0 }

    expect(verifyBinary(pk, ciphertext, tampered)).toBe(false)
  })

  it('rejects a tampered proof (flipped bit in e1)', () => {
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(1, pk)
    const proof = proveBinary(1, randomness, pk, ciphertext)

    const tamperedE1 = new Uint8Array(proof.e1)
    tamperedE1[0] ^= 0x01
    const tampered = { ...proof, e1: tamperedE1 }

    expect(verifyBinary(pk, ciphertext, tampered)).toBe(false)
  })

  it('rejects when wrong ciphertext is paired with a valid proof', () => {
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(0, pk)
    const proof = proveBinary(0, randomness, pk, ciphertext)

    // Use a different ciphertext with the same proof
    const { ciphertext: otherCt } = encrypt(1, pk)
    expect(verifyBinary(pk, otherCt, proof)).toBe(false)
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
      const proof = proveBinary(bit, encResults[i].randomness, pk, encResults[i].ciphertext)
      expect(verifyBinary(pk, encResults[i].ciphertext, proof)).toBe(true)
    }

    const cts = encResults.map(r => r.ciphertext)
    const sodium = getSodium()
    let rSum = encResults[0].randomness
    for (let i = 1; i < encResults.length; i++) {
      rSum = sodium.crypto_core_ristretto255_scalar_add(rSum, encResults[i].randomness)
    }
    const sumProof = proveSumOne(cts, rSum, pk)
    expect(verifySumOne(pk, cts, sumProof)).toBe(true)
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
    const sumProof = proveSumOne(cts, rSum, pk)
    expect(verifySumOne(pk, cts, sumProof)).toBe(true)
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
      const proof = proveBinary(bit, encResults[i].randomness, pk, encResults[i].ciphertext)
      expect(verifyBinary(pk, encResults[i].ciphertext, proof)).toBe(true)
    }

    const cts = encResults.map(r => r.ciphertext)
    const sodium = getSodium()
    let rSum = encResults[0].randomness
    for (let i = 1; i < encResults.length; i++) {
      rSum = sodium.crypto_core_ristretto255_scalar_add(rSum, encResults[i].randomness)
    }
    const sumProof = proveSumOne(cts, rSum, pk)
    expect(verifySumOne(pk, cts, sumProof)).toBe(true)
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
    const sumProof = proveSumOne(cts, rSum, pk)
    expect(verifySumOne(pk, cts, sumProof)).toBe(true)
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

    const proof = proveSumOne(cts, rSum, pk)
    expect(verifySumOne(pk, cts, proof)).toBe(true)
  })

  it('verifies a single-element vector encrypting 1', () => {
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(1, pk)
    const proof = proveSumOne([ciphertext], randomness, pk)
    expect(verifySumOne(pk, [ciphertext], proof)).toBe(true)
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
    const proof = proveSumOne(cts, rSum, pk)

    // The proof is for the aggregate of all-zeros, which encrypts 0, not 1.
    // Verification checks h^z == b + (aggC2 - g)*e. Since aggC2 = h^rSum (no g),
    // the equation won't hold with the Schnorr relation for rSum.
    expect(verifySumOne(pk, cts, proof)).toBe(false)
  })

  it('rejects a tampered proof (modified z)', () => {
    const sodium = getSodium()
    const { pk } = makeKeyPair()

    const r0 = encrypt(0, pk)
    const r1 = encrypt(1, pk)
    const cts = [r0.ciphertext, r1.ciphertext]
    const rSum = sodium.crypto_core_ristretto255_scalar_add(r0.randomness, r1.randomness)

    const proof = proveSumOne(cts, rSum, pk)

    const tamperedZ = new Uint8Array(proof.z)
    tamperedZ[0] ^= 0xff
    const tampered = { ...proof, z: tamperedZ }

    expect(verifySumOne(pk, cts, tampered)).toBe(false)
  })
})
