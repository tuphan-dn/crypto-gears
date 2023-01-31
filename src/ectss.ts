import {
  CURVE,
  Point,
  getPublicKey,
  sign,
  utils,
  Signature,
  verify,
} from '@noble/secp256k1'
import BN from 'bn.js'
import { SecretSharing } from './sss'
import { FiniteField } from './ff'
import { CryptoScheme } from './types'

/**
 * ECCurve
 */
export class ECCurve {
  static scheme: CryptoScheme = 'ecdsa'
  static ff = FiniteField.fromBigInt(CURVE.P, 'be')

  static baseMul = (r: Uint8Array): Uint8Array => {
    const b = BigInt(new BN(r, 16, 'be').toString())
    return Point.BASE.multiply(b).toRawBytes(true)
  }

  static addPoint = (pointA: Uint8Array, pointB: Uint8Array): Uint8Array => {
    const a = Point.fromHex(pointA)
    const b = Point.fromHex(pointB)
    return a.add(b).toRawBytes(true)
  }

  static mulScalar = (point: Uint8Array, scalar: Uint8Array): Uint8Array => {
    const p = Point.fromHex(point)
    const s = BigInt(new BN(scalar, 16, 'be').toString())
    return p.multiply(s).toRawBytes(true)
  }
}

export class ECUtil {
  static randomnessLength = 32
  static ff = FiniteField.fromBigInt(CURVE.n, 'be')

  static shareRandomness = (t: number, n: number) => {
    const r = this.ff.norm(utils.randomBytes(ECUtil.randomnessLength))
    const secretSharing = new SecretSharing(this.ff.r, 'be')
    const shares = secretSharing.share(r, t, n)
    const R = ECCurve.baseMul(r)
    return { shares, R }
  }

  static getPublicKey = (privateKey: Uint8Array) =>
    getPublicKey(privateKey, true)

  static sign = (msg: Uint8Array, privateKey: Uint8Array) =>
    sign(msg, privateKey)
}

/**
 * ECTSS
 */
export class ECTSS {
  static ff = FiniteField.fromBigInt(CURVE.n, 'be')
  static messageHashLength = 32
  static privateKeyLength = 32
  static publicKeyLength = 33

  static finalizeSig = (sig: Signature): Uint8Array => {
    if (sig.hasHighS()) sig = sig.normalizeS()
    return sig.toDERRawBytes()
  }

  /**
   * Add partial signatures
   * @param sigs Partial signatures
   * @returns
   */
  static addSig = (...sigs: Uint8Array[]): Uint8Array => {
    const rs = sigs
      .map(Signature.fromDER)
      .map(({ r }) => new BN(r.toString()).toRed(this.ff.r))
    const ss = sigs
      .map(Signature.fromDER)
      .map(({ s }) => new BN(s.toString()).toRed(this.ff.r))
    // Compute R
    const R = BigInt(
      rs
        .reduce((sum, r) => sum.redAdd(r), new BN(0).toRed(this.ff.r))
        .toString(),
    )
    // Compute S
    const S = BigInt(
      ss
        .reduce((sum, s) => sum.redAdd(s), new BN(0).toRed(this.ff.r))
        .toString(),
    )
    // Concat
    const sig = new Signature(R, S)
    return this.finalizeSig(sig)
  }

  /**
   * Partially signs the message by each holder
   * @param msgHash Message
   * @param R Randomness
   * @param r Shared randomness
   * @param privateKey Private key
   * @returns
   */
  static sign = (
    // Public
    msgHash: Uint8Array,
    R: Uint8Array,
    // Private
    r: Uint8Array,
    privateKey: Uint8Array,
  ) => {
    if (msgHash.length !== ECTSS.messageHashLength)
      throw new Error('bad message hash size')
    if (r.length !== ECUtil.randomnessLength)
      throw new Error('bad randomness size')
    if (privateKey.length !== ECTSS.privateKeyLength)
      throw new Error('bad private key size')

    const h = ECTSS.ff.norm(msgHash)
    const s = this.ff.mul(
      this.ff.inv(r),
      this.ff.add(h, this.ff.mul(R, privateKey)),
    )

    const sig = new Signature(
      BigInt(this.ff.encode(R).toString()),
      BigInt(this.ff.encode(s).toString()),
    )
    return this.finalizeSig(sig)
  }

  /**
   * Verify the message.
   * It's identical to the secp256k1 verification.
   */
  static verify = (msg: Uint8Array, sig: Uint8Array, pubkey: Uint8Array) =>
    verify(sig, msg, pubkey, { strict: false })
}
