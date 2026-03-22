import { describe, it, expect, beforeAll } from 'vitest'
import { initSodium, getSodium } from '../sodium'
import {
  encrypt,
  homomorphicAdd,
  serializeCiphertext,
  deserializeCiphertext,
  bytesToHex,
  hexToBytes,
} from '../elgamal'

beforeAll(async () => {
  await initSodium()
})

function makeKeyPair() {
  const sodium = getSodium()
  const sk = sodium.crypto_core_ristretto255_scalar_random()
  const pk = sodium.crypto_scalarmult_ristretto255_base(sk)
  return { sk, pk }
}

describe('encrypt', () => {
  it('produces 32-byte c1 and c2', () => {
    const { pk } = makeKeyPair()
    const { ciphertext } = encrypt(0, pk)
    expect(ciphertext.c1).toBeInstanceOf(Uint8Array)
    expect(ciphertext.c2).toBeInstanceOf(Uint8Array)
    expect(ciphertext.c1.length).toBe(32)
    expect(ciphertext.c2.length).toBe(32)
  })

  it('m=0 and m=1 produce different c2 for same randomness key', () => {
    const { pk } = makeKeyPair()
    const res0 = encrypt(0, pk)
    const res1 = encrypt(1, pk)
    // c2 must differ (with overwhelming probability); c1 may also differ (fresh r each call)
    expect(res0.ciphertext.c2).not.toEqual(res1.ciphertext.c2)
  })

  it('uses fresh randomness per call — c1 differs between calls', () => {
    const { pk } = makeKeyPair()
    const res1 = encrypt(0, pk)
    const res2 = encrypt(0, pk)
    // With overwhelming probability two independent random scalars differ
    expect(res1.ciphertext.c1).not.toEqual(res2.ciphertext.c1)
  })

  it('returns a 32-byte randomness scalar', () => {
    const { pk } = makeKeyPair()
    const { randomness } = encrypt(0, pk)
    expect(randomness).toBeInstanceOf(Uint8Array)
    expect(randomness.length).toBe(32)
  })

  it('c1 = g^r (matches manual computation)', () => {
    const sodium = getSodium()
    const { pk } = makeKeyPair()
    const { ciphertext, randomness } = encrypt(0, pk)
    const expectedC1 = sodium.crypto_scalarmult_ristretto255_base(randomness)
    expect(ciphertext.c1).toEqual(expectedC1)
  })
})

describe('homomorphicAdd', () => {
  it('produces a valid 32-byte ciphertext', () => {
    const { pk } = makeKeyPair()
    const { ciphertext: a } = encrypt(0, pk)
    const { ciphertext: b } = encrypt(1, pk)
    const sum = homomorphicAdd(a, b)
    expect(sum.c1.length).toBe(32)
    expect(sum.c2.length).toBe(32)
  })

  it('c1 of sum equals point-addition of c1s', () => {
    const sodium = getSodium()
    const { pk } = makeKeyPair()
    const { ciphertext: a } = encrypt(0, pk)
    const { ciphertext: b } = encrypt(0, pk)
    const sum = homomorphicAdd(a, b)
    const expectedC1 = sodium.crypto_core_ristretto255_add(a.c1, b.c1)
    expect(sum.c1).toEqual(expectedC1)
  })
})

describe('serialize / deserialize', () => {
  it('round-trips correctly', () => {
    const { pk } = makeKeyPair()
    const { ciphertext } = encrypt(1, pk)
    const hex = serializeCiphertext(ciphertext)
    const back = deserializeCiphertext(hex)
    expect(back.c1).toEqual(ciphertext.c1)
    expect(back.c2).toEqual(ciphertext.c2)
  })

  it('produces 128 hex characters', () => {
    const { pk } = makeKeyPair()
    const { ciphertext } = encrypt(0, pk)
    const hex = serializeCiphertext(ciphertext)
    expect(hex.length).toBe(128)
    expect(hex).toMatch(/^[0-9a-f]{128}$/)
  })

  it('throws on invalid hex length', () => {
    expect(() => deserializeCiphertext('deadbeef')).toThrow()
  })
})

describe('bytesToHex / hexToBytes', () => {
  it('round-trips correctly', () => {
    const bytes = new Uint8Array([0x00, 0x0f, 0xff, 0xab, 0x12])
    expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes)
  })

  it('produces lowercase hex', () => {
    const bytes = new Uint8Array([0xab, 0xcd, 0xef])
    expect(bytesToHex(bytes)).toBe('abcdef')
  })
})
