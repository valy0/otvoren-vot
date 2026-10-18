// Hex helpers with no runtime dependencies, so code that only needs to decode
// hex (such as the public-key pin check) does not pull in libsodium.

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Decodes hex (either case) to bytes. Throws on an odd length or any
 * character outside [0-9a-fA-F]; parseInt alone would read "zz" as 0 and
 * " f" or "+f" as 15.
 */
export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  if (hex.length % 2 !== 0) throw new Error('Hex string must have even length')
  if (!/^[0-9a-f]*$/i.test(hex)) throw new Error('Hex string has a non-hex character')
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}
