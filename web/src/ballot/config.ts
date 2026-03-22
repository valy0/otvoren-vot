// ---------------------------------------------------------------------------
// Election configuration — fetched from the Bulletin Board
// ---------------------------------------------------------------------------

export interface Party {
  name: string
  candidates: string[]
}

export interface ElectionConfig {
  electionId: string
  publicKey: string  // hex, 64 chars (32-byte Ristretto255 point)
  parties: Party[]
}

// Bulletin Board API response shape
interface BBElectionResponse {
  data: {
    election_id: string
    public_key: string
    parties: Array<{ name: string; candidates: string[] }>
  }
}

/**
 * Fetches election configuration from the Bulletin Board and optionally
 * verifies the public key against the pinned hash in VITE_ELECTION_PUBKEY_HASH.
 *
 * Throws if:
 *   - Network request fails
 *   - Response shape is unexpected
 *   - VITE_ELECTION_PUBKEY_HASH is set and the public key hash does not match
 */
export async function fetchElectionConfig(bbUrl: string): Promise<ElectionConfig> {
  const url = `${bbUrl}/api/v1/election`
  let res: Response
  try {
    res = await fetch(url)
  } catch (err) {
    throw new Error(`Failed to reach Bulletin Board at ${url}: ${String(err)}`)
  }

  if (!res.ok) {
    throw new Error(`Bulletin Board returned HTTP ${res.status} for ${url}`)
  }

  let body: BBElectionResponse
  try {
    body = (await res.json()) as BBElectionResponse
  } catch {
    throw new Error('Bulletin Board returned invalid JSON')
  }

  const { data } = body
  if (!data || typeof data.election_id !== 'string' || typeof data.public_key !== 'string') {
    throw new Error('Bulletin Board response is missing required fields (election_id, public_key)')
  }
  if (!Array.isArray(data.parties)) {
    throw new Error('Bulletin Board response is missing parties array')
  }

  const publicKey = data.public_key

  // Verify public key hash if env var is configured
  const expectedHash = import.meta.env.VITE_ELECTION_PUBKEY_HASH as string | undefined
  if (expectedHash) {
    await verifyPublicKeyHash(publicKey, expectedHash)
  } else {
    console.warn(
      '[otvoren-vot] VITE_ELECTION_PUBKEY_HASH is not set. ' +
      'Election public key is NOT pinned — running in dev/insecure mode.',
    )
  }

  return {
    electionId: data.election_id,
    publicKey,
    parties: data.parties.map(p => ({ name: p.name, candidates: p.candidates ?? [] })),
  }
}

// ---------------------------------------------------------------------------
// Internal: public key hash verification
// ---------------------------------------------------------------------------

/**
 * Decodes a hex public key, computes SHA-256 over the raw bytes, and compares
 * the digest (hex) against the expected hash.
 */
async function verifyPublicKeyHash(publicKeyHex: string, expectedHashHex: string): Promise<void> {
  // Decode hex → raw bytes
  if (publicKeyHex.length % 2 !== 0) {
    throw new Error('CRITICAL: Election public key verification failed — invalid hex length')
  }
  const bytes = new Uint8Array(publicKeyHex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(publicKeyHex.slice(i * 2, i * 2 + 2), 16)
  }

  // SHA-256 via Web Crypto API (available in all target environments)
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes)
  const hashBytes = new Uint8Array(hashBuffer)
  const actualHash = Array.from(hashBytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')

  if (actualHash.toLowerCase() !== expectedHashHex.toLowerCase()) {
    throw new Error(
      'CRITICAL: Election public key verification failed. ' +
      `Expected SHA-256 ${expectedHashHex}, got ${actualHash}. ` +
      'The election configuration may have been tampered with.',
    )
  }
}
