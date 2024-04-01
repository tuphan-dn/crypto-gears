import { Point } from '@noble/ed25519'
import { ed25519 } from '@noble/curves/ed25519'
import { sha512 } from '@noble/hashes/sha512'
import { keccak_256 } from '@noble/hashes/sha3'
import BN from 'bn.js'
import { SecretSharing } from './sss'
import { FiniteField } from './ff'
import { concatBytes, randomBytes } from '@noble/hashes/utils'
import { equal } from './utils'

/**
 * EdCurve
 */
export class EdCurve {
  static ff = FiniteField.fromBigInt(ed25519.CURVE.n, 'le')
  static ZERO = Point.ZERO.toRawBytes()

  static validate = (point: Uint8Array): boolean => {
    try {
      Point.fromHex(point)
      return true
    } catch (er) {
      return false
    }
  }

  static baseMul = (r: Uint8Array) => {
    if (this.ff.ZERO.eq(this.ff.encode(r))) return Point.ZERO.toRawBytes()
    const b = BigInt(new BN(r, 16, this.ff.en).toString())
    return Point.BASE.multiply(b).toRawBytes()
  }

  static negPoint = (point: Uint8Array) => {
    const a = Point.fromHex(point)
    return a.negate().toRawBytes()
  }

  static addPoint = (pointA: Uint8Array, pointB: Uint8Array) => {
    if (equal([pointA, Point.ZERO.toRawBytes()])) return pointB
    if (equal([pointB, Point.ZERO.toRawBytes()])) return pointA
    const a = Point.fromHex(pointA)
    const b = Point.fromHex(pointB)
    return a.add(b).toRawBytes()
  }

  static mulScalar = (point: Uint8Array, scalar: Uint8Array) => {
    if (
      equal([point, Point.ZERO.toRawBytes()]) ||
      this.ff.ZERO.eq(this.ff.encode(scalar))
    )
      return Point.ZERO.toRawBytes()
    const p = Point.fromHex(point)
    const s = BigInt(new BN(scalar, 16, this.ff.en).toString())
    return p.multiply(s).toRawBytes()
  }

  static getDerivedKey = (privateKey: Uint8Array) => {
    const derivedKey = sha512(privateKey.subarray(0, 32)).subarray(0, 32)
    derivedKey[0] &= 248
    derivedKey[31] &= 127
    derivedKey[31] |= 64
    return this.ff.norm(derivedKey)
  }

  static getPublicKey = (privateKey: Uint8Array, derived = false) => {
    if (!derived) privateKey = this.getDerivedKey(privateKey)
    const pubkey = this.baseMul(privateKey)
    return pubkey
  }
}

/**
 * EdTSS
 */
export class EdTSS {
  static ff = FiniteField.fromBigInt(ed25519.CURVE.n, 'le')
  static signatureLength = 64
  static privateKeyLength = 32
  static publicKeyLength = 32
  static randomnessLength = 32

  static shareRandomness = (
    t: number,
    n: number,
    indice: Uint8Array[],
    seed?: Uint8Array,
  ) => {
    const r = this.ff.norm(
      !seed ? randomBytes(EdTSS.randomnessLength) : keccak_256(seed),
    )
    const secretSharing = new SecretSharing(this.ff)
    const { shares, zkp } = secretSharing.share(r, t, n, {
      indice,
      ec: EdCurve,
    })
    const R = EdCurve.baseMul(r)
    return { shares, R, r, zkp }
  }

  /**
   * Add partial signatures
   * @param sigs Partial signatures
   * @returns
   */
  static addSig = (sigs: Uint8Array[]): Uint8Array => {
    const rs = sigs.map((sig) => sig.subarray(0, 32))
    const ss = sigs.map((sig) => sig.subarray(32))
    // Compute R
    const R = rs.reduce(
      (sum, r) => EdCurve.addPoint(sum, r),
      Point.ZERO.toRawBytes(),
    )
    // Compute S
    const S = ss.reduce(
      (sum, s) => this.ff.add(sum, s),
      this.ff.decode(new BN(0)),
    )
    // Concat
    return concatBytes(R, S)
  }

  /**
   * Partially signs the message by each holder
   * @param msg Message
   * @param R Randomness
   * @param publicKey Master public key
   * @param r Shared randomness
   * @param derivedKey Derived key
   * @returns
   */
  static sign = (
    // Public
    msg: Uint8Array,
    R: Uint8Array,
    publicKey: Uint8Array,
    // Private
    r: Uint8Array,
    derivedKey: Uint8Array,
  ) => {
    if (r.length !== this.randomnessLength)
      throw new Error('bad randomness size')
    if (derivedKey.length !== this.privateKeyLength)
      throw new Error('bad private key size')
    if (publicKey.length !== EdTSS.publicKeyLength)
      throw new Error('bad public key size')

    // h = sha512(R || pub || msg)
    const h = sha512(concatBytes(R, publicKey, msg))
    // [s] = [r] + h * [priv]
    const s = this.ff.add(this.ff.mul(h, derivedKey), r)
    // [R] = [r]G
    const rG = EdCurve.baseMul(r)
    return concatBytes(rG, s)
  }

  /**
   * Verify the commitment by zkp
   * @param msg Message
   * @param R Randomness
   * @param publicKey Master public key
   * @param index Signer id
   * @param pzkp The zk proof of the private key
   * @param rzkp The zk proof of the randomness
   */
  static verify = (
    // Public
    msg: Uint8Array,
    R: Uint8Array,
    publicKey: Uint8Array,
    index: Uint8Array,
    // Witness
    sig: Uint8Array,
    pzkp: Uint8Array[],
    rzkp: Uint8Array[],
  ) => {
    if (publicKey.length !== EdTSS.publicKeyLength)
      throw new Error('bad public key size')
    if (pzkp.length !== rzkp.length) throw new Error('bad proofs size')

    const x = this.ff.decode(new BN(index, 8, this.ff.en))
    // h = sha512(R || pub || msg)
    const h = sha512(concatBytes(R, publicKey, msg))
    // sig = [R] || [s]
    const rG = sig.subarray(0, this.publicKeyLength)
    const s = sig.subarray(this.publicKeyLength, this.signatureLength)
    // _rG = rzkp[0] + rzkp[1] * index + rzkp[2] * index^2 + ...
    const _rG = rzkp.reduce(
      (sum, co, i) =>
        EdCurve.addPoint(sum, EdCurve.mulScalar(co, this.ff.pow(x, i))),
      EdCurve.ZERO,
    )
    if (!equal([_rG, rG])) return false
    // [s]G = ([r] + h * [priv])G = [r]G + h * [priv]G
    // [s]G = [r]G + h * (pzkp[0] + pzkp[1] * index + pzkp[2] * index^2 + ...)
    const sG = EdCurve.baseMul(s)
    const _sG = EdCurve.addPoint(
      rG,
      EdCurve.mulScalar(
        pzkp.reduce(
          (sum, co, i) =>
            EdCurve.addPoint(sum, EdCurve.mulScalar(co, this.ff.pow(x, i))),
          EdCurve.ZERO,
        ),
        this.ff.norm(h),
      ),
    )
    return equal([_sG, sG])
  }
}
