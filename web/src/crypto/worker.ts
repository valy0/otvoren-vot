import { initSodium, getSodium } from './sodium'
import { buildBallot } from './ballotBuilder'
import type { SerializedBinaryProof, SerializedSumOneProof } from './ballotBuilder'

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

export type WorkerRequest = {
  type: 'encrypt-ballot'
  electionId: string      // election ID from the Bulletin Board; bound into every proof
  electionPubKey: string  // hex 64 chars (32 bytes Ristretto255 point)
  partyIndex: number      // 0..numParties (last = blank vote)
  numParties: number
  candidateIndex?: number  // -1 = no preference, 0..numCandidates-1 = preference
  numCandidates?: number   // 0 if blank vote
  requestId?: string       // caller-generated ID to match responses
}

export type WorkerResponse =
  | {
      type: 'encrypt-result'
      requestId?: string
      ballotId: string
      encryptedBallot: { party_vector: string[]; candidate_vectors: string[][] }
      zkProofs: {
        binary_party: SerializedBinaryProof[]
        sum_one: SerializedSumOneProof
        binary_candidate?: SerializedBinaryProof[]
        sum_one_candidate?: SerializedSumOneProof
      }
    }
  | {
      type: 'encrypt-error'
      requestId?: string
      message: string
    }

// ---------------------------------------------------------------------------
// Worker message handler
// ---------------------------------------------------------------------------

self.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const req = event.data

  if (req.type !== 'encrypt-ballot') {
    const response: WorkerResponse = {
      type: 'encrypt-error',
      message: `Unknown request type: ${String((req as { type: unknown }).type)}`,
    }
    self.postMessage(response)
    return
  }

  try {
    await initSodium()
    self.postMessage(buildBallot(req, getSodium()))
  } catch (err) {
    const response: WorkerResponse = {
      type: 'encrypt-error',
      requestId: req.requestId,
      message: err instanceof Error ? err.message : String(err),
    }
    self.postMessage(response)
  }
}
