import { bytesToHex } from '@noble/hashes/utils'

export const equal = (...arr: Uint8Array[]): boolean => {
  if (!arr) return true
  const [a, ...rest] = arr
  const index = rest.findIndex((b) => bytesToHex(a) !== bytesToHex(b))
  return index < 0
}
