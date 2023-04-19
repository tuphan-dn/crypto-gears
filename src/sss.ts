/**
 * Shamir's Secret Sharing Scheme
 * Implemented by Tu Phan <tuphan@descartes.network>
 *
 * The implementation is available for t-out-of-n models
 * The share is in little-endian format
 * - [0,8,index] [8,16,t] [16,24,n] [24,32,id] [32,64,share]
 * - The tuple (t,n,id) must be identical to all shares in a same group
 */

import { concatBytes, randomBytes } from '@noble/hashes/utils'
import { FiniteField } from './ff'

export type ExtractedShare = {
  index: Uint8Array // 8 bytes
  t: Uint8Array // 8 bytes
  n: Uint8Array // 8 bytes
  id: Uint8Array // 8 bytes
  share: Uint8Array // 32 bytes
}

const allEqual = (arr: Uint8Array[]): boolean => {
  if (!arr) return true
  const [a, ...rest] = arr
  const index = rest.findIndex((b) => Buffer.compare(a, b) !== 0)
  return index < 0
}

export class SecretSharing {
  constructor(public readonly ff: FiniteField) {}

  static shareLength = 64

  /**
   * Convert a share from bytes-like array to human-readable object
   * @param share Bytes-like array
   * @returns Human-readable object
   */
  static extract = (share: Uint8Array): ExtractedShare => ({
    index: share.subarray(0, 8),
    t: share.subarray(8, 16),
    n: share.subarray(16, 24),
    id: share.subarray(24, 32),
    share: share.subarray(32, 64),
  })

  /**
   * Convet a share from human-readable object to bytes-like array
   * @param opts ExtractedShare
   * @returns Bytes-like array
   */
  static compress = ({ index, t, n, id, share }: ExtractedShare) =>
    concatBytes(index, t, n, id, share)

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
    if (this.ff.numberToRedBN(indice.length).lt(this.ff.encode(t)))
      throw new Error('Not enough required number of shares')
    return { indice, t, n: ns[0], id: ids[0] }
  }

  pi = (
    indice: Uint8Array[],
    index: Uint8Array = this.ff.decode(this.ff.ZERO, 8),
  ): Uint8Array[] => {
    return indice.map((a, i) =>
      indice.reduce(
        (prod, o, j) =>
          i !== j
            ? this.ff.mul(
                this.ff.mul(
                  this.ff.inv(this.ff.sub(o, a)),
                  this.ff.sub(o, index),
                ),
                prod,
              )
            : prod,
        this.ff.decode(this.ff.ONE),
      ),
    )
  }

  yl = (y: Uint8Array, l: Uint8Array): Uint8Array => this.ff.mul(y, l)

  /**
   * Derive the efficient of the highest term
   * @param shares Secret shares
   * @returns The highest efficient
   */
  ft1 = (shares: Uint8Array[]): Uint8Array => {
    const xs = shares.map((share) => share.subarray(0, 8)).map(this.ff.encode)
    const ls = xs
      .map((x, i) =>
        xs.reduce(
          (prod, o, j) => (i !== j ? x.redSub(o).redInvm().redMul(prod) : prod),
          this.ff.ONE,
        ),
      )
      .map((l) => this.ff.decode(l, 32))
    const ys = shares.map((share) => share.subarray(32, 64))
    return ys.reduce(
      (sum, y, i) => this.ff.add(this.yl(y, ls[i]), sum),
      this.ff.decode(this.ff.ZERO),
    )
  }

  /**
   * Lagrange Interpolation
   * @param index The x coordinate
   * @param shares The sufficient number of shares
   * @returns The y coordinate
   */
  interpolate = (index: Uint8Array, shares: Uint8Array[]): Uint8Array => {
    const { indice } = this.validateShares(shares)
    const ls = this.pi(indice, index)
    const ys = shares.map((share) => share.subarray(32, 64))
    return ys.reduce(
      (sum, y, i) => this.ff.add(this.yl(y, ls[i]), sum),
      this.ff.decode(this.ff.ZERO),
    )
  }

  /**
   * Recontruct the original secret from its shares
   * @param shares List of shares
   * @returns The original secret
   */
  construct = (shares: Uint8Array[]): Uint8Array => {
    return this.interpolate(this.ff.decode(this.ff.ZERO, 8), shares)
  }

  /**
   * Split a secret into multiple shares. The algorithm allows t of n shares able to reconstruct the secret.
   * @param key The secret (Must be less than `this.red`)
   * @param t The threshold
   * @param n The total number of shares
   * @returns List of shares
   */
  share = (
    key: Uint8Array,
    t: number,
    n: number,
    indice: Uint8Array[] = [],
    id: Uint8Array = randomBytes(8),
  ): Uint8Array[] => {
    if (t < 1 || n < 1 || t > n) throw new Error('Invalid t-out-of-n format')
    if (id && id.length !== 8)
      throw new Error('id must be an 8-length bytes-like array')
    // Group identity
    const T = this.ff.decode(this.ff.numberToRedBN(t), 8)
    const N = this.ff.decode(this.ff.numberToRedBN(n), 8)
    const ID = id
    // Randomize coefficients
    const coefficients = [key]
    while (coefficients.length < t) coefficients.push(this.ff.rand())
    // Build the polynomial
    const y = (x: Uint8Array): Uint8Array =>
      coefficients.reduce(
        (sum, co, i) => this.ff.add(this.ff.mul(this.ff.pow(x, i), co), sum),
        this.ff.decode(this.ff.ZERO),
      )
    // Compute shares
    const xs: Uint8Array[] = [...indice]
    while (xs.length < n) xs.push(randomBytes(8))
    const shares = xs.map((x) => y(x))
    return shares.map((s, i) => concatBytes(xs[i], T, N, ID, s))
  }

  /**
   * Proactivate the shares
   * @param t The threshold
   * @param n The total number of shares
   * @param id Next shares id
   * @returns List of next shares
   */
  proactivate = (
    t: number,
    n: number,
    indice: Uint8Array[],
    id: Uint8Array = randomBytes(8),
  ) => {
    if (n !== indice.length) throw new Error('Not enough index')
    const zero = this.ff.decode(this.ff.ZERO, 32)
    const updates = this.share(zero, t, n, indice, id)
    return updates
  }

  /**
   * Merge the current share with an update to the next share
   * @param prev The current share
   * @param next The update
   * @returns The next share
   */
  merge = (prev: Uint8Array, next: Uint8Array) => {
    if (
      prev.length !== SecretSharing.shareLength ||
      next.length !== SecretSharing.shareLength
    )
      throw new Error('Invalid share length')
    if (!allEqual([prev.subarray(0, 8), next.subarray(0, 8)]))
      throw new Error('Cannot merge irrelevant shares')
    const i = next.subarray(0, 8)
    const t = next.subarray(8, 16)
    const n = next.subarray(16, 24)
    const id = next.subarray(24, 32)
    const a = this.ff.add(prev.subarray(32), next.subarray(32))
    return concatBytes(i, t, n, id, a)
  }
}
