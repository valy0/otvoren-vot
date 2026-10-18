// Drives the worker's message handler with a stand-in for the worker scope:
// every failure inside buildBallot must reach the page as an encrypt-error.
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import { initSodium, getSodium } from '../sodium'
import { bytesToHex } from '../elgamal'
import type { WorkerRequest, WorkerResponse } from '../worker'

interface WorkerScope {
  onmessage: ((event: MessageEvent<WorkerRequest>) => Promise<void>) | null
  postMessage: (message: WorkerResponse) => void
}

const posted: WorkerResponse[] = []
const scope: WorkerScope = { onmessage: null, postMessage: message => { posted.push(message) } }

beforeAll(async () => {
  await initSodium()
  vi.stubGlobal('self', scope)
  await import('../worker')
})

afterAll(() => {
  vi.unstubAllGlobals()
})

async function send(req: WorkerRequest): Promise<WorkerResponse> {
  posted.length = 0
  if (scope.onmessage === null) throw new Error('worker did not install onmessage')
  await scope.onmessage({ data: req } as MessageEvent<WorkerRequest>)
  expect(posted).toHaveLength(1)
  return posted[0]
}

/** A public key, hex, with a byte below 0x10 (its hex starts with '0'). */
function publicKeyWithLeadingZeroNibble(): { hex: string; byte: number } {
  const sodium = getSodium()
  for (;;) {
    const pk = sodium.crypto_scalarmult_ristretto255_base(sodium.crypto_core_ristretto255_scalar_random())
    const byte = pk.findIndex(b => b < 0x10)
    if (byte >= 0) return { hex: bytesToHex(pk), byte }
  }
}

function request(electionPubKey: string, electionId = 'election-1'): WorkerRequest {
  return {
    type: 'encrypt-ballot', electionId, electionPubKey,
    partyIndex: 0, numParties: 2, candidateIndex: -1, numCandidates: 1, requestId: 'req-1',
  }
}

describe('worker', () => {
  it('encrypts a valid request', async () => {
    const res = await send(request(publicKeyWithLeadingZeroNibble().hex))
    expect(res.type).toBe('encrypt-result')
    expect(res.requestId).toBe('req-1')
  })

  // ' X' and '+X' parse as 0X under parseInt, so the key would still decode to
  // the same valid point; strict hex must refuse it.
  it('answers encrypt-error for a public key with a non-hex character', async () => {
    const { hex, byte } = publicKeyWithLeadingZeroNibble()
    for (const sign of ['+', ' ']) {
      const bad = hex.slice(0, 2 * byte) + sign + hex.slice(2 * byte + 1)
      expect(bad).toHaveLength(64)
      const res = await send(request(bad))
      expect(res.type).toBe('encrypt-error')
      expect(res.requestId).toBe('req-1')
      if (res.type === 'encrypt-error') expect(res.message).toMatch(/hex/i)
    }
  })

  it('answers encrypt-error for an empty election id', async () => {
    const res = await send(request(publicKeyWithLeadingZeroNibble().hex, ''))
    expect(res.type).toBe('encrypt-error')
    if (res.type === 'encrypt-error') expect(res.message).toMatch(/election id/)
  })
})
