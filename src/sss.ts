/**
 * Shamir's Secret Sharing Scheme
 * Implemented by Tu Phan <tuphan@descartes.network>
 *
 * The implementation is available for t-out-of-n models
 * The share is in little-endian format
 * - [0,8,index] [8,16,t] [16,24,n] [24,32,id] [32,63,share]
 * - The tuple (t,n,id) must be identical to all shares in a same group
 */

import { CURVE, utils } from '@noble/ed25519'
import BN from 'bn.js'

export type RedBN = ReturnType<BN['toRed']>
export type ExtractedShare = {
  index: BN
  t: BN
  n: BN
  id: BN
  share: BN
}

export const shareLength = 64
export const allEquals = (arr: BN[]): boolean => {
  for (let i = 0; i < arr.length; i++)
    for (let j = i + 1; j < arr.length; j++)
      if (!arr[i].eq(arr[j])) return false
  return true
}

class SecretSharing {
  constructor(public readonly red: BN.ReductionContext) {}

  static EdDSA = BN.red(new BN(CURVE.l.toString()))
  static ECDSA = BN.red(new BN(2))

  private validateShares = (shares: Uint8Array[]) => {
    shares.forEach((share) => {
      if (share.length !== shareLength) throw new Error('Invalid share length')
    })
    const indice = shares.map((share) => share.subarray(0, 8))
    const ts = shares.map((share) => new BN(share.subarray(8, 16), 16, 'le'))
    const ns = shares.map((share) => new BN(share.subarray(16, 24), 16, 'le'))
    const ids = shares.map((share) => new BN(share.subarray(24, 32), 16, 'le'))
    if (!allEquals(ts) || !allEquals(ns) || !allEquals(ids))
      throw new Error('The shares is not in a same group')
    const t = ts[0]
    if (new BN(indice.length).lt(t))
      throw new Error('Not enough required number of shares')
    return { indice, t, n: ns[0], id: ids[0] }
  }

  pi = (indice: Uint8Array[]): Uint8Array[] => {
    const xs = indice.map((index) => new BN(index, 16, 'le').toRed(this.red))
    return xs
      .map((x, i) => {
        let p = new BN(1).toRed(this.red)
        xs.forEach((o, j) => {
          if (i !== j) p = p.redMul(o.redMul(o.redSub(x).redInvm()))
        })
        return p
      })
      .map((l) => l.toArrayLike(Buffer, 'le', 32))
  }

  yl = (y: Uint8Array, l: Uint8Array): Uint8Array => {
    const _y = new BN(y, 16, 'le').toRed(this.red)
    const _l = new BN(l, 16, 'le').toRed(this.red)
    return _y.redMul(_l).toArrayLike(Buffer, 'le', 32)
  }

  private sigma = (ys: Uint8Array[], ls: Uint8Array[]): Uint8Array => {
    let sum = new BN(0).toRed(this.red)
    ys.map((y, i) => {
      const _yl = new BN(this.yl(y, ls[i]), 16, 'le').toRed(this.red)
      sum = _yl.redAdd(sum)
    })
    return sum.toArrayLike(Buffer, 'le', 32)
  }

  extract = (share: Uint8Array): ExtractedShare => {
    this.validateShares([share])
    return {
      index: new BN(share.subarray(0, 8), 16, 'le'),
      t: new BN(share.subarray(8, 16), 16, 'le'),
      n: new BN(share.subarray(16, 24), 16, 'le'),
      id: new BN(share.subarray(24, 32), 16, 'le'),
      share: new BN(share.subarray(32, 64), 16, 'le'),
    }
  }

  construct = (shares: Uint8Array[]): Uint8Array => {
    const { indice } = this.validateShares(shares)
    const ys = shares.map((share) => share.subarray(32, 64))
    const ls = this.pi(indice)
    return this.sigma(ys, ls)
  }

  share = (key: Uint8Array, t: number, n: number): Uint8Array[] => {
    if (t < 2 || n < 2 || t > n) throw new Error('Invalid t-out-of-n format')
    // Group identity
    const T = new BN(t).toArrayLike(Buffer, 'le', 8)
    const N = new BN(n).toArrayLike(Buffer, 'le', 8)
    const ID = utils.randomBytes(8)
    // Randomize coefficients
    const a = new BN(key, 16, 'le').toRed(this.red)
    const coefficients = [a]
    for (let i = 0; i < t; i++) {
      const r = new BN(utils.randomBytes(32), 16, 'le').toRed(this.red)
      coefficients.push(r)
    }
    // Build the polynomial
    const y = (x: RedBN): RedBN => {
      let sum = new BN(0).toRed(this.red)
      for (let i = 0; i < t; i++) {
        const k = new BN(i)
        sum = x.redPow(k).redMul(coefficients[i]).redAdd(sum)
      }
      return sum
    }
    // Compute shares
    const shares: RedBN[] = []
    for (let i = 0; i < n; i++) {
      const x = new BN(i + 1).toRed(this.red)
      shares.push(y(x))
    }
    return shares.map((x, i) => {
      let share = new Uint8Array(64)
      const k = new BN(i + 1).toArrayLike(Buffer, 'le', 8)
      const s = x.toArrayLike(Buffer, 'le', 32)
      for (let i = 0; i < 8; i++) share[i] = k[i]
      for (let i = 0; i < 8; i++) share[8 + i] = T[i]
      for (let i = 0; i < 8; i++) share[16 + i] = N[i]
      for (let i = 0; i < 8; i++) share[24 + i] = ID[i]
      for (let i = 0; i < 32; i++) share[32 + i] = s[i]
      return share
    })
  }
}

export default SecretSharing
