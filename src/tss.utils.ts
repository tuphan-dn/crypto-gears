import { reduceL } from './utils'
import { hash, randomBytes } from './retweetnacl'

const {
  lowlevel: { gf, pack, add, scalarbase, modL },
} = require('./retweetnacl')

export const derivedKeyLength = 32
export const randomnessLength = 64

export const randL = (): Uint8Array => {
  const r = new Uint8Array(randomnessLength)
  modL(r, randomBytes(randomnessLength))
  return r
}

export const getDerivedKey = (secretKey: Uint8Array) => {
  const derivedKey = hash(secretKey.subarray(0, 32)).subarray(
    0,
    derivedKeyLength,
  )
  derivedKey[0] &= 248
  derivedKey[31] &= 127
  derivedKey[31] |= 64
  return reduceL(derivedKey)
}

export const genRandomness = (num = 1) => {
  const r: Uint8Array[] = []
  for (let i = 0; i < num; i++) r.push(randL())
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
