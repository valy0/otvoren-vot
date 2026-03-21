// ---------------------------------------------------------------------------
// Ballot submission — posts encrypted ballot to the Collection Server
// ---------------------------------------------------------------------------

export interface BallotReceipt {
  ballotId: string
  position: number
  merkleRoot: string
  isOverride: boolean
}

// Collection Server response shape
interface CollectionSubmitResponse {
  data: {
    ballot_id: string
    position: number
    merkle_root: string
    is_override: boolean
  }
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
): Promise<BallotReceipt> {
  const url = `${collectionUrl}/api/v1/submit`

  let res: Response
  try {
    res = await fetch(url, {
      method: 'POST',
      credentials: 'include',  // send session cookie
      headers: { 'Content-Type': 'application/json' },
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

  const { data } = body
  if (
    !data ||
    typeof data.ballot_id !== 'string' ||
    typeof data.position !== 'number' ||
    typeof data.merkle_root !== 'string' ||
    typeof data.is_override !== 'boolean'
  ) {
    throw new Error('Collection Server response is missing required receipt fields')
  }

  return {
    ballotId: data.ballot_id,
    position: data.position,
    merkleRoot: data.merkle_root,
    isOverride: data.is_override,
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
