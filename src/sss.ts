/**
 * Shamir's Secret Sharing Scheme
 * Implemented by Tu Phan <tuphan@descartes.network>
 *
 * The implementation is available for t-out-of-n models
 * The share is in little-endian format
 * - [0,8,index] [8,16,t] [16,24,n] [24,32,id] [32,64,share]
 * - The tuple (t,n,id) must be identical to all shares in a same group
 */

import { utils } from '@noble/ed25519'
import BN from 'bn.js'
import { RedBN } from './ff'

export type ExtractedShare = {
  index: Uint8Array // 8 bytes
  t: Uint8Array // 8 bytes
  n: Uint8Array // 8 bytes
  id: Uint8Array // 8 bytes
  share: Uint8Array // 32 bytes
}

const allEqual = (arr: Uint8Array[]): boolean => {
  for (let i = 0; i < arr.length; i++)
    for (let j = i + 1; j < arr.length; j++)
      if (Buffer.compare(arr[i], arr[j]) !== 0) return false
  return true
}

export class SecretSharing {
  constructor(
    public readonly red: BN.ReductionContext,
    public readonly end: BN.Endianness = 'le',
  ) {}

  static shareLength = 64

  static extract = (share: Uint8Array): ExtractedShare => ({
    index: share.subarray(0, 8),
    t: share.subarray(8, 16),
    n: share.subarray(16, 24),
    id: share.subarray(24, 32),
    share: share.subarray(32, 64),
  })
  static compress = ({ index, t, n, id, share }: ExtractedShare) =>
    utils.concatBytes(index, t, n, id, share)

  private toBN = (n: ConstructorParameters<typeof BN>[0]) =>
    new BN(n, 16, this.end).toRed(this.red)
  private fromBN = (n: RedBN, l: number): Uint8Array =>
    Uint8Array.from(n.toArray(this.end, l))

  private validateShares = (shares: Uint8Array[]) => {
    shares.forEach((share) => {
      if (share.length !== SecretSharing.shareLength)
        throw new Error('Invalid share length')
    })
    const indice = shares.map((share) => SecretSharing.extract(share).index)
    const ts = shares.map((share) => SecretSharing.extract(share).t)
    const ns = shares.map((share) => SecretSharing.extract(share).n)
    const ids = shares.map((share) => SecretSharing.extract(share).id)
    if (!allEqual(ts) || !allEqual(ns) || !allEqual(ids))
      throw new Error('The shares are not in a same group')
    const t = ts[0]
    if (this.toBN(indice.length).lt(this.toBN(t)))
      throw new Error('Not enough required number of shares')
    return { indice, t, n: ns[0], id: ids[0] }
  }

  pi = (indice: Uint8Array[]): Uint8Array[] => {
    const xs = indice.map(this.toBN)
    return xs
      .map((x, i) =>
        xs.reduce(
          (prod, o, j) =>
            i !== j ? o.redSub(x).redInvm().redMul(o).redMul(prod) : prod,
          this.toBN(1),
        ),
      )
      .map((l) => this.fromBN(l, 32))
  }

  yl = (y: Uint8Array, l: Uint8Array): Uint8Array => {
    const _y = this.toBN(y)
    const _l = this.toBN(l)
    return this.fromBN(_y.redMul(_l), 32)
  }

  private sigma = (ys: Uint8Array[], ls: Uint8Array[]): Uint8Array => {
    const sum = ys.reduce(
      (sum, y, i) => this.toBN(this.yl(y, ls[i])).redAdd(sum),
      this.toBN(0),
    )
    return this.fromBN(sum, 32)
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
    const T = this.fromBN(this.toBN(t), 8)
    const N = this.fromBN(this.toBN(n), 8)
    const ID = utils.randomBytes(8)
    // Randomize coefficients
    const a = this.toBN(key)
    const coefficients = [a]
    while (coefficients.length < t)
      coefficients.push(this.toBN(utils.randomBytes(32)))
    // Build the polynomial
    const y = (x: RedBN): RedBN =>
      coefficients.reduce(
        (sum, co, i) => x.redPow(new BN(i)).redMul(co).redAdd(sum),
        this.toBN(0),
      )
    // Compute shares
    const shares: RedBN[] = []
    for (let i = 0; i < n; i++) shares.push(y(this.toBN(i + 1)))
    return shares.map((s, i) =>
      utils.concatBytes(
        this.fromBN(this.toBN(i + 1), 8),
        T,
        N,
        ID,
        this.fromBN(s, 32),
      ),
    )
  }
}
