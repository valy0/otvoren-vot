import { getSodium } from './sodium'

/**
 * Fiat-Shamir challenge computation for Sigma protocols.
 *
 * MUST match Go's internal.FiatShamir (crypto/internal/scalar.go) byte for
 * byte; the format is specified in docs/protocol/fiat-shamir.md:
 * - SHA-512 hash
 * - 4-byte big-endian uint32 length prefix on domain separator
 * - 4-byte big-endian uint32 length prefix on each data element
 * - SHA-512 output (64 bytes) reduced to a scalar mod ℓ
 *
 * crypto_core_ristretto255_scalar_reduce and Go's ristretto255
 * Scalar.SetUniformBytes both reduce the 64-byte little-endian digest modulo
 * the Ristretto255 group order ℓ, producing identical scalars.
 */
export function fiatShamir(domain: string, ...data: Uint8Array[]): Uint8Array {
  const sodium = getSodium()
  const domainBytes = new TextEncoder().encode(domain)
  let totalSize = 4 + domainBytes.length
  for (const d of data) totalSize += 4 + d.length

  const buf = new Uint8Array(totalSize)
  const view = new DataView(buf.buffer)
  let offset = 0

  // Domain with 4-byte big-endian length prefix
  view.setUint32(offset, domainBytes.length, false)
  offset += 4
  buf.set(domainBytes, offset)
  offset += domainBytes.length

  // Each data element with 4-byte big-endian length prefix
  for (const d of data) {
    view.setUint32(offset, d.length, false)
    offset += 4
    buf.set(d, offset)
    offset += d.length
  }

  const digest = sodium.crypto_hash_sha512(buf)
  return sodium.crypto_core_ristretto255_scalar_reduce(digest)
}
