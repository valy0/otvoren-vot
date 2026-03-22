import sodiumLib from 'libsodium-wrappers-sumo'

let _sodium: typeof sodiumLib | null = null

export async function initSodium(): Promise<typeof sodiumLib> {
  if (_sodium) return _sodium
  await sodiumLib.ready
  _sodium = sodiumLib
  return sodiumLib
}

export function getSodium(): typeof sodiumLib {
  if (!_sodium) throw new Error('Sodium not initialized. Call initSodium() first.')
  return _sodium
}
