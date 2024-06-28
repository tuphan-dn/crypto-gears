/**
 * Shamir's Secret Sharing Scheme by Tu Phan <tuphan@gears.bot>
 * The implementation is available for t-out-of-n models
 * The share is in little-endian/big-endian format depending on the Finite Field
 * - [0,8,index] [8,16,t] [16,24,n] [24,32,id] [32,64,share]
 * - The tuple (t,n,id) must be identical to all shares in a same group
 */

import { concatBytes, randomBytes } from '@noble/hashes/utils'
import FBN, { FiniteField } from './fbn'
import { equal } from './utils'
import BN from 'bn.js'
import { Poly } from './poly'

export type ExtractedSecretShare = {
  index: Uint8Array // 8 bytes
  t: Uint8Array // 8 bytes
  n: Uint8Array // 8 bytes
  id: Uint8Array // 8 bytes
  secret: Uint8Array // 32 bytes
}

export class SecretSharing {
  constructor(public readonly ff: FiniteField) {}

  static shareLength = 64

  /**
   * Convert a share from bytes-like array to human-readable object
   * @param share Bytes-like array
   * @returns Human-readable object
   */
  static extract = (share: Uint8Array): ExtractedSecretShare => ({
    index: share.subarray(0, 8),
    t: share.subarray(8, 16),
    n: share.subarray(16, 24),
    id: share.subarray(24, 32),
    secret: share.subarray(32, 64),
  })

  /**
   * Convet a share from human-readable object to bytes-like array
   * @param opts ExtractedShare
   * @returns Bytes-like array
   */
  static compress = ({ index, t, n, id, secret }: ExtractedSecretShare) =>
    concatBytes(index, t, n, id, secret)

  private _check = (shares: Uint8Array[]) => {
    shares.forEach((share) => {
      if (share.length !== SecretSharing.shareLength)
        throw new Error('Invalid share length')
    })
    const indice = shares.map((share) => SecretSharing.extract(share).index)
    const ts = shares.map((share) => SecretSharing.extract(share).t)
    const ns = shares.map((share) => SecretSharing.extract(share).n)
    const ids = shares.map((share) => SecretSharing.extract(share).id)
    if (!equal(...ts) || !equal(...ns) || !equal(...ids))
      throw new Error('The shares are not in a same group')
    const [t] = ts
    const [n] = ns
    const [id] = ids
    if (new BN(indice.length, 16, this.ff.en).lt(new BN(t, 16, this.ff.en)))
      throw new Error('Not enough required number of shares')
    return { indice, t, n, id }
  }

  /**
   * Lagrange basis
   * @param indice The list of known x
   * @param index The point to interpolate
   * @returns
   */
  basis = (indice: FBN[], index: FBN = this.ff.ZERO): FBN[] => {
    const involved = indice.findIndex((i) => i.eq(index))
    // Edge cases
    if (involved >= 0)
      return indice.map((_, i) => (i === involved ? this.ff.ONE : this.ff.ZERO))
    // Common cases
    const shared = indice.reduce(
      (prod, e) => index.sub(e).mul(prod),
      this.ff.ONE,
    )
    return indice.map((a, i) =>
      indice
        .reduce((p, b, j) => (i !== j ? a.sub(b).mul(p) : p), this.ff.ONE)
        .mul(index.sub(a))
        .inv()
        .mul(shared),
    )
  }

  /**
   * Derive the coefficient of the highest term
   * @param shares Secret shares
   * @returns The highest coefficient
   */
  ft1 = (shares: Uint8Array[]): Uint8Array => {
    const { indice, t } = this._check(shares)
    const _t = this.ff.norm(t).toNumber()
    const xs = indice.map((index) => this.ff.norm(index)).slice(0, _t)
    const ys = shares
      .map((share) => this.ff.norm(share.subarray(32, 64)))
      .slice(0, _t)
    const basis = xs.map((a, i) =>
      xs
        .reduce((p, b, j) => (i !== j ? a.sub(b).mul(p) : p), this.ff.ONE)
        .inv(),
    )
    return ys
      .reduce((sum, y, i) => sum.add(y.mul(basis[i])), this.ff.ZERO)
      .serialize()
  }

  /**
   * Lagrange Interpolation
   * @param index The x coordinate
   * @param shares The sufficient number of shares
   * @returns The y coordinate
   */
  interpolate = (index: Uint8Array, shares: Uint8Array[]): FBN => {
    const { indice } = this._check(shares)
    const basis = this.basis(indice.map(this.ff.norm), this.ff.norm(index))
    const ys = shares.map((share) => this.ff.norm(share.subarray(32, 64)))
    return ys.reduce((sum, y, i) => sum.add(y.mul(basis[i])), this.ff.ZERO)
  }

  /**
   * Recontruct the original secret from its shares
   * @param shares List of shares
   * @returns The original secret
   */
  construct = (shares: Uint8Array[]): Uint8Array => {
    return this.interpolate(this.ff.ZERO.serialize(), shares).serialize()
  }

  /**
   * Split a secret into multiple shares. The algorithm allows t of n shares able to reconstruct the secret.
   * @param key The secret (Must be less than `this.red`)
   * @param t The threshold
   * @param n The total number of shares
   * @param opts.indice Predefined indexes
   * @param opts.id Predefined id
   * @param opts.ec Elliptic Curve if you want to return the zk proofs
   * @returns List of shares and zkps
   */
  share = (
    key: Uint8Array,
    t: number,
    n: number,
    {
      indice = [],
      id = randomBytes(8),
    }: {
      indice?: Uint8Array[]
      id?: Uint8Array
    } = {},
  ): Uint8Array[] => {
    if (t < 1 || n < 1 || t > n) throw new Error('Invalid t-out-of-n format.')
    if (id && id.length !== 8)
      throw new Error('Id must be an 8-length bytes-like array.')
    // Randomize coefficients
    const coefficients = [this.ff.norm(key)]
    while (coefficients.length < t) coefficients.push(this.ff.rand())
    const poly = new Poly(coefficients)
    // Compute shares
    const xs = indice.map((index) => this.ff.norm(index))
    while (xs.length < n) xs.push(this.ff.rand(8))
    const shares = xs
      .map((x) => poly.y(x))
      .map((s, i) =>
        SecretSharing.compress({
          index: xs[i].serialize(8),
          t: this.ff.norm(t).serialize(8),
          n: this.ff.norm(n).serialize(8),
          id,
          secret: s.serialize(),
        }),
      )
    return shares
  }

  /**
   * Proactivate the shares
   * @param t The threshold
   * @param n The total number of shares
   * @param indice The list of indexes
   * @param opts.id Predefined next shares id
   * @returns List of next shares
   */
  proactivate = (
    t: number,
    n: number,
    indice: Uint8Array[],
    {
      id = randomBytes(8),
    }: {
      id?: Uint8Array
    } = {},
  ) => {
    if (n !== indice.length) throw new Error('Not enough number of indexes.')
    const zero = this.ff.ZERO.serialize()
    const updates = this.share(zero, t, n, { indice, id })
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
      throw new Error('Invalid share length.')
    if (!equal(prev.subarray(0, 8), next.subarray(0, 8)))
      throw new Error('Cannot merge irrelevant shares.')
    const index = next.subarray(0, 8)
    const t = next.subarray(8, 16)
    const n = next.subarray(16, 24)
    const id = next.subarray(24, 32)
    const secret = this.ff
      .norm(prev.subarray(32))
      .add(this.ff.norm(next.subarray(32)))
      .serialize()
    return SecretSharing.compress({ index, t, n, id, secret })
  }
}
