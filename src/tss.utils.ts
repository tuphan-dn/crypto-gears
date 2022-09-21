import BN from 'bn.js'
import { hash, randomBytes } from './retweetnacl'

const {
  lowlevel: { gf, pack, add, scalarbase, modL, L },
} = require('./retweetnacl')

export const derivedKeyLength = 32
export const randomnessLength = 64

export function getDerivedKey(secretKey: Uint8Array) {
  const derivedKey = hash(secretKey.subarray(0, 32)).subarray(
    0,
    derivedKeyLength,
  )
  derivedKey[0] &= 248
  derivedKey[31] &= 127
  derivedKey[31] |= 64
  return derivedKey
}

export function genRandomness(num = 1) {
  const r: Uint8Array[] = []
  for (let i = 0; i < num; i++) {
    const _r = new Uint8Array(randomnessLength)
    modL(_r, randomBytes(randomnessLength))
    r.push(_r)
  }
  let sum
  r.forEach((_r) => {
    const _R = [gf(), gf(), gf(), gf()]
    scalarbase(_R, _r)
    if (!sum) sum = _R
    else add(sum, _R)
  })
  const R = new Uint8Array(32)
  pack(R, sum)
  return { r, R }
}

export function addScalars(a: Uint8Array, b: Uint8Array): Uint8Array {
  const red = BN.red(new BN(L, 16, 'le'))
  const _a = new BN(a, 16, 'le').toRed(red)
  const _b = new BN(b, 16, 'le').toRed(red)
  return _a.redAdd(_b).toArrayLike(Buffer, 'le', 32)
}
