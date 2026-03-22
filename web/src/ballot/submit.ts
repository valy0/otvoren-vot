// ---------------------------------------------------------------------------
// Ballot submission — posts encrypted ballot to the Collection Server
// ---------------------------------------------------------------------------

export interface BallotReceipt {
  ballotId: string
  position: number
  merkleRoot: string
  isOverride: boolean
}

// Collection Server response shape (fields at top level)
interface CollectionSubmitResponse {
  ballot_id: string
  position: number
  merkle_root: string
  is_override: boolean
}

/**
 * Submits an encrypted ballot to the Collection Server.
 *
 * Uses `credentials: 'include'` so the voter's session cookie is sent.
 *
 * Throws on:
 *   - 401 Unauthorized (session expired)
 *   - Any non-2xx HTTP status
 *   - Network errors or malformed response
 */
export async function submitBallot(
  collectionUrl: string,
  ballotId: string,
  encryptedBallot: object,
  zkProofs: object,
  bearerToken?: string,
): Promise<BallotReceipt> {
  const url = `${collectionUrl}/api/v1/submit`

  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (bearerToken) {
    headers['Authorization'] = `Bearer ${bearerToken}`
  }

  let res: Response
  try {
    res = await fetch(url, {
      method: 'POST',
      credentials: 'include',  // send session cookie
      headers,
      body: JSON.stringify({
        ballot_id: ballotId,
        encrypted_ballot: encryptedBallot,
        zk_proofs: zkProofs,
      }),
    })
  } catch (err) {
    throw new Error(`Failed to reach Collection Server at ${url}: ${String(err)}`)
  }

  if (res.status === 401) {
    throw new SessionExpiredError('Сесията е изтекла. Моля, удостоверете се отново.')
  }

  if (!res.ok) {
    let detail = ''
    try {
      const text = await res.text()
      detail = text ? `: ${text}` : ''
    } catch {
      // ignore parse failure; use empty detail
    }
    throw new Error(`Collection Server returned HTTP ${res.status}${detail}`)
  }

  let body: CollectionSubmitResponse
  try {
    body = (await res.json()) as CollectionSubmitResponse
  } catch {
    throw new Error('Collection Server returned invalid JSON')
  }

  if (
    typeof body.ballot_id !== 'string' ||
    typeof body.position !== 'number' ||
    typeof body.merkle_root !== 'string' ||
    typeof body.is_override !== 'boolean'
  ) {
    throw new Error('Collection Server response is missing required receipt fields')
  }

  return {
    ballotId: body.ballot_id,
    position: body.position,
    merkleRoot: body.merkle_root,
    isOverride: body.is_override,
  }
}

// ---------------------------------------------------------------------------
// Sentinel error type for session expiry (allows caller to direct to re-auth)
// ---------------------------------------------------------------------------

export class SessionExpiredError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SessionExpiredError'
  }
}
