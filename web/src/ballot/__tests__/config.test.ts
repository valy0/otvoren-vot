import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { fetchElectionConfig } from '../config'

// The Ristretto255 generator: a valid 32-byte point, hex.
const PUBLIC_KEY = 'e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76'

function stubBulletinBoard(data: unknown): void {
  vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(new Response(JSON.stringify({ data }), { status: 200 }))))
}

beforeEach(() => {
  // VITE_ELECTION_PUBKEY_HASH is unset in tests; silence the dev-mode warning.
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('fetchElectionConfig', () => {
  it('returns the election configuration', async () => {
    stubBulletinBoard({ election_id: 'election-1', public_key: PUBLIC_KEY, parties: [{ name: 'A', candidates: ['x'] }] })
    await expect(fetchElectionConfig('http://bb.test')).resolves.toEqual({
      electionId: 'election-1',
      publicKey: PUBLIC_KEY,
      parties: [{ name: 'A', candidates: ['x'] }],
    })
  })

  it('rejects an empty election_id: every ballot proof is bound to it', async () => {
    stubBulletinBoard({ election_id: '', public_key: PUBLIC_KEY, parties: [] })
    await expect(fetchElectionConfig('http://bb.test')).rejects.toThrow(/election_id/)
  })
})
