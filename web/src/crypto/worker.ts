import { initSodium, getSodium } from './sodium'
import { encrypt, serializeCiphertext, hexToBytes, bytesToHex } from './elgamal'
import { proveBinary, proveSumOne } from './proofs'
import type { BinaryProof, SumOneProof } from './proofs'

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

export type WorkerRequest = {
  type: 'encrypt-ballot'
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

// Serialized proof types (all Uint8Array fields become hex strings)
interface SerializedBinaryProof {
  a0: string; b0: string; a1: string; b1: string
  e0: string; e1: string; z0: string; z1: string
}

interface SerializedSumOneProof {
  a: string; b: string; z: string
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

function serializeBinaryProof(p: BinaryProof): SerializedBinaryProof {
  return {
    a0: bytesToHex(p.a0), b0: bytesToHex(p.b0),
    a1: bytesToHex(p.a1), b1: bytesToHex(p.b1),
    e0: bytesToHex(p.e0), e1: bytesToHex(p.e1),
    z0: bytesToHex(p.z0), z1: bytesToHex(p.z1),
  }
}

function serializeSumOneProof(p: SumOneProof): SerializedSumOneProof {
  return {
    a: bytesToHex(p.a),
    b: bytesToHex(p.b),
    z: bytesToHex(p.z),
  }
}

/** Base64url-encodes a Uint8Array without padding. */
function toBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
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
    // Step 1: Ensure sodium is initialized
    await initSodium()
    const sodium = getSodium()

    // Step 2: Decode the election public key
    if (req.electionPubKey.length !== 64) {
      throw new Error(`Invalid election public key length: expected 64 hex chars, got ${req.electionPubKey.length}`)
    }
    const pubKey = hexToBytes(req.electionPubKey)

    // Step 3: Generate a 256-bit ballot ID (32 random bytes, base64url encoded)
    const ballotIdBytes = sodium.randombytes_buf(32)
    const ballotId = toBase64Url(ballotIdBytes)

    // Step 4: Build the one-hot party vector and encrypt each element
    // partyIndex range is now 0..numParties (inclusive; last = blank vote)
    const { partyIndex, numParties } = req
    if (partyIndex < 0 || partyIndex > numParties) {
      throw new Error(`partyIndex ${partyIndex} out of range [0, ${numParties}]`)
    }

    const partyVectorLen = numParties + 1  // +1 for blank vote slot
    const encResults = Array.from({ length: partyVectorLen }, (_, i) =>
      encrypt(i === partyIndex ? 1 : 0, pubKey)
    )

    // Step 5: Generate binary proof for each party element
    const binaryProofs = encResults.map((res, i) =>
      proveBinary(i === partyIndex ? 1 : 0, res.randomness, pubKey, res.ciphertext)
    )

    // Step 6: Sum all randomness scalars, then generate sum=1 proof
    const randomnessScalars = encResults.map(r => r.randomness)
    let rSum = randomnessScalars[0]
    for (let i = 1; i < randomnessScalars.length; i++) {
      rSum = sodium.crypto_core_ristretto255_scalar_add(rSum, randomnessScalars[i])
    }

    const cts = encResults.map(r => r.ciphertext)
    const sumProof = proveSumOne(cts, rSum, pubKey)

    // Step 7: Zero all randomness scalars
    for (const r of randomnessScalars) {
      sodium.memzero(r)
    }
    sodium.memzero(rSum)

    // Step 8: Serialize ciphertexts and proofs to hex strings for JSON transport
    const partyVector = cts.map(ct => serializeCiphertext(ct))
    const serializedBinaryProofs = binaryProofs.map(serializeBinaryProof)
    const serializedSumProof = serializeSumOneProof(sumProof)

    // Step 9: Candidate vector encryption (if candidates provided)
    let candidateVector: string[] = []
    let candidateBinaryProofs: SerializedBinaryProof[] = []
    let candidateSumProof: SerializedSumOneProof | null = null

    const numCandidates = req.numCandidates ?? 0
    const candidateIndex = req.candidateIndex ?? -1

    if (numCandidates > 0) {
      const candVectorLen = numCandidates + 1  // +1 for "no preference" virtual slot
      // -1 means no preference → select last slot
      const activeSlot = candidateIndex === -1 ? candVectorLen - 1 : candidateIndex

      const candEncResults = Array.from({ length: candVectorLen }, (_, i) =>
        encrypt(i === activeSlot ? 1 : 0, pubKey)
      )

      // Binary proofs for each candidate element
      const candBinaryRaw = candEncResults.map((res, i) =>
        proveBinary(i === activeSlot ? 1 : 0, res.randomness, pubKey, res.ciphertext)
      )

      // Sum-one proof for candidate vector
      const candRandomness = candEncResults.map(r => r.randomness)
      let candRSum = candRandomness[0]
      for (let i = 1; i < candRandomness.length; i++) {
        candRSum = sodium.crypto_core_ristretto255_scalar_add(candRSum, candRandomness[i])
      }
      const candCts = candEncResults.map(r => r.ciphertext)
      const candSumProofRaw = proveSumOne(candCts, candRSum, pubKey)

      // Zero randomness
      for (const r of candRandomness) { sodium.memzero(r) }
      sodium.memzero(candRSum)

      // Serialize
      candidateVector = candCts.map(ct => serializeCiphertext(ct))
      candidateBinaryProofs = candBinaryRaw.map(serializeBinaryProof)
      candidateSumProof = serializeSumOneProof(candSumProofRaw)
    }

    const response: WorkerResponse = {
      type: 'encrypt-result',
      requestId: req.requestId,
      ballotId,
      encryptedBallot: {
        party_vector: partyVector,
        candidate_vectors: candidateVector.length > 0 ? [candidateVector] : [],
      },
      zkProofs: {
        binary_party: serializedBinaryProofs,
        sum_one: serializedSumProof,
        binary_candidate: candidateBinaryProofs.length > 0 ? candidateBinaryProofs : undefined,
        sum_one_candidate: candidateSumProof ?? undefined,
      },
    }

    self.postMessage(response)
  } catch (err) {
    const response: WorkerResponse = {
      type: 'encrypt-error',
      requestId: req.requestId,
      message: err instanceof Error ? err.message : String(err),
    }
    self.postMessage(response)
  }
}
