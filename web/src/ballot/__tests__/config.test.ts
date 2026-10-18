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
  vi.unstubAllEnvs()
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

  describe('with a pinned public key hash', () => {
    async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
      return Array.from(digest, b => b.toString(16).padStart(2, '0')).join('')
    }

    const pinFor = (hex: string) =>
      sha256Hex(Uint8Array.from(hex.match(/../g) ?? [], pair => parseInt(pair, 16)))

    // The key with a "00" byte, and the same key with "zz" in its place: a
    // lenient parseInt decode reads "zz" as 0, so both hash to the same digest.
    const GOOD_KEY = '00' + PUBLIC_KEY.slice(2)
    const BAD_KEY = 'zz' + PUBLIC_KEY.slice(2)

    it('accepts the pinned key', async () => {
      vi.stubEnv('VITE_ELECTION_PUBKEY_HASH', await pinFor(GOOD_KEY))
      stubBulletinBoard({ election_id: 'election-1', public_key: GOOD_KEY, parties: [] })
      await expect(fetchElectionConfig('http://bb.test')).resolves.toMatchObject({ publicKey: GOOD_KEY })
    })

    it('rejects a key with a non-hex character whose lenient decode would match the pin', async () => {
      vi.stubEnv('VITE_ELECTION_PUBKEY_HASH', await pinFor(GOOD_KEY))
      stubBulletinBoard({ election_id: 'election-1', public_key: BAD_KEY, parties: [] })
      await expect(fetchElectionConfig('http://bb.test')).rejects.toThrow(/CRITICAL: Election public key verification failed — .*non-hex/)
    })
  })
})
