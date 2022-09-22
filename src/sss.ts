/**
 * Shamir's Secret Sharing Scheme
 * Implemented by Tu Phan <tuphan@descartes.network>
 */

import BN from 'bn.js'
import { randomBytes } from './retweetnacl'
const {
  lowlevel: { L },
} = require('./retweetnacl')

const red = BN.red(new BN(L, 16, 'le'))

export type RedBN = ReturnType<BN['toRed']>

export const share = (key: Uint8Array, t: number, n: number): Uint8Array[] => {
  if (t < 2 || n < 2 || t > n) throw new Error('Invalid t-out-of-n format')
  // Rand coefficients
  const a = new BN(key, 16, 'le').toRed(red)
  const coefficients = [a]
  for (let i = 0; i < t; i++) {
    const r = new BN(randomBytes(32), 16, 'le').toRed(red)
    coefficients.push(r)
  }
  // Build the polynomial
  const y = (x: RedBN): RedBN => {
    let sum = new BN(0).toRed(red)
    for (let i = 0; i < t; i++) {
      const k = new BN(i)
      sum = x.redPow(k).redMul(coefficients[i]).redAdd(sum)
    }
    return sum
  }
  // Compute share
  const shares: RedBN[] = []
  for (let i = 0; i < n; i++) {
    const x = new BN(i + 1).toRed(red)
    shares.push(y(x))
  }
  return shares.map((x, i) => {
    let share = new Uint8Array(64)
    const k = new BN(i + 1).toArrayLike(Buffer, 'le', 32)
    const s = x.toArrayLike(Buffer, 'le', 32)
    for (let i = 0; i < 32; i++) {
      share[i] = k[i]
      share[32 + i] = s[i]
    }
    return share
  })
}

export const precompute = (indice: Uint8Array[]): Uint8Array[] => {
  const xs = indice.map((index) => new BN(index, 16, 'le').toRed(red))
  return xs
    .map((x, i) => {
      let p = new BN(1).toRed(red)
      xs.map((o, j) => {
        if (i !== j) p = p.redMul(o.redMul(o.redSub(x).redInvm()))
      })
      return p
    })
    .map((l) => l.toArrayLike(Buffer, 'le', 32))
}

export const construct = (shares: Uint8Array[]): Uint8Array => {
  const indice = shares.map((share) => share.subarray(0, 32))
  const ys = shares.map((share) => share.subarray(32, 64))
  const ls = precompute(indice)
  let sum = new BN(0).toRed(red)
  ys.map((y, i) => {
    const l = ls[i]
    const _y = new BN(y, 16, 'le').toRed(red)
    const _l = new BN(l, 16, 'le').toRed(red)
    sum = _y.redMul(_l).redAdd(sum)
  })
  return sum.toArrayLike(Buffer, 'le', 32)
}
