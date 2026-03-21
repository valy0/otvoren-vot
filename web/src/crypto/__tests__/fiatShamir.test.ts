import { describe, it, expect, beforeAll } from 'vitest'
import { initSodium, getSodium } from '../sodium'
import { fiatShamir } from '../fiatShamir'

beforeAll(async () => {
  await initSodium()
})

describe('fiatShamir', () => {
  it('produces a 32-byte output', () => {
    const sodium = getSodium()
    const data = sodium.crypto_core_ristretto255_scalar_random()
    const result = fiatShamir('test-domain', data)
    expect(result).toBeInstanceOf(Uint8Array)
    expect(result.length).toBe(32)
  })

  it('is deterministic — same inputs yield same output', () => {
    const sodium = getSodium()
    const data = sodium.crypto_core_ristretto255_scalar_random()
    const r1 = fiatShamir('deterministic-domain', data)
    const r2 = fiatShamir('deterministic-domain', data)
    expect(r1).toEqual(r2)
  })

  it('produces different outputs for different domain separators', () => {
    const sodium = getSodium()
    const data = sodium.crypto_core_ristretto255_scalar_random()
    const r1 = fiatShamir('domain-a', data)
    const r2 = fiatShamir('domain-b', data)
    expect(r1).not.toEqual(r2)
  })

  it('produces different outputs for different data', () => {
    const sodium = getSodium()
    const d1 = sodium.crypto_core_ristretto255_scalar_random()
    const d2 = sodium.crypto_core_ristretto255_scalar_random()
    const r1 = fiatShamir('same-domain', d1)
    const r2 = fiatShamir('same-domain', d2)
    expect(r1).not.toEqual(r2)
  })

  it('encodes length-prefix correctly — prepending extra byte changes result', () => {
    // Ensures the 4-byte big-endian length prefix is actually used:
    // domain "ab" with data [0x00, 0x01] must differ from
    // domain "a" with data [0x62, 0x00, 0x01]  (0x62 = 'b')
    const d = new Uint8Array([0x00, 0x01])
    const r1 = fiatShamir('ab', d)
    const r2 = fiatShamir('a', new Uint8Array([0x62, 0x00, 0x01]))
    expect(r1).not.toEqual(r2)
  })

  it('handles multiple data elements', () => {
    const sodium = getSodium()
    const d1 = sodium.crypto_core_ristretto255_scalar_random()
    const d2 = sodium.crypto_core_ristretto255_scalar_random()
    const result = fiatShamir('multi-domain', d1, d2)
    expect(result).toBeInstanceOf(Uint8Array)
    expect(result.length).toBe(32)
  })
})
