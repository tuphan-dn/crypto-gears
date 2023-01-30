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
import { RedBN } from './ff'
import { CryptoScheme } from './types'

/**
 * ECCurve
 */
export class ECCurve {
  static scheme: CryptoScheme = 'ecdsa'

  static red = BN.red(new BN(CURVE.n.toString()))

  static encode = (r: Uint8Array): RedBN =>
    new BN(r, 16, 'be').toRed(ECCurve.red)

  static decode = (r: BN, length: number): Uint8Array =>
    r.toArrayLike(Buffer, 'be', length)

  static normalize = (r: Uint8Array): Uint8Array =>
    ECCurve.decode(ECCurve.encode(r), r.length)

  static baseMul = (r: Uint8Array): Uint8Array => {
    const bn = ECCurve.encode(r)
    const bi = BigInt(bn.toString())
    return Point.BASE.multiply(bi).toRawBytes(true)
  }

  static addPoint = (pointA: Uint8Array, pointB: Uint8Array): Uint8Array => {
    const a = Point.fromHex(pointA)
    const b = Point.fromHex(pointB)
    return a.add(b).toRawBytes(true)
  }

  static mulScalar = (point: Uint8Array, scalar: Uint8Array): Uint8Array => {
    const p = Point.fromHex(point)
    const s = BigInt(ECCurve.encode(scalar).toString())
    return p.multiply(s).toRawBytes(true)
  }
}

export class ECUtil {
  static randomnessLength = 32

  static shareRandomness = (t: number, n: number) => {
    const r = ECCurve.normalize(utils.randomBytes(ECUtil.randomnessLength))
    const secretSharing = new SecretSharing(ECCurve.red, 'be')
    const shares = secretSharing.share(r, t, n)
    const R = ECCurve.baseMul(r)
    return { shares, R }
  }

  static getPublicKey = (privateKey: Uint8Array) => {
    return getPublicKey(privateKey, true)
  }

  static sign = (
    msg: Uint8Array,
    privateKey: Uint8Array,
  ): Promise<Uint8Array> => {
    return sign(msg, privateKey)
  }

  static finalizeSig = (sig: Signature): Uint8Array => {
    if (sig.hasHighS()) sig = sig.normalizeS()
    return sig.toDERRawBytes()
  }
}

/**
 * ECTSS
 */
export class ECTSS {
  static messageHashLength = 32
  static privateKeyLength = 32
  static publicKeyLength = 33

  /**
   * Add partial signatures
   * @param sigs Partial signatures
   * @returns
   */
  static addSig = (...sigs: Uint8Array[]): Uint8Array => {
    const rs = sigs
      .map(Signature.fromDER)
      .map(({ r }) => new BN(r.toString()).toRed(ECCurve.red))
    const ss = sigs
      .map(Signature.fromDER)
      .map(({ s }) => new BN(s.toString()).toRed(ECCurve.red))
    // Compute R
    const R = BigInt(
      rs
        .reduce((sum, r) => sum.redAdd(r), new BN(0).toRed(ECCurve.red))
        .toString(),
    )
    // Compute S
    const S = BigInt(
      ss
        .reduce((sum, s) => sum.redAdd(s), new BN(0).toRed(ECCurve.red))
        .toString(),
    )
    // Concat
    const sig = new Signature(R, S)
    return ECUtil.finalizeSig(sig)
  }

  /**
   * Partially signs the message by each holder
   * @param msg Message
   * @param R Randomness
   * @param publicKey Master public key
   * @param r Shared randomness
   * @param privateKey Derived key
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
      throw new Error('bad privte key size')

    const s = ECCurve.encode(privateKey)
      .redMul(ECCurve.encode(R))
      .redAdd(ECCurve.encode(msgHash))
      .redMul(ECCurve.encode(r))
    const sig = new Signature(
      BigInt(ECCurve.encode(R).toString()),
      BigInt(s.toString()),
    )
    return ECUtil.finalizeSig(sig)
  }

  /**
   * Verify the message.
   * It's identical to the secp256k1 verification.
   */
  static verify = (msg: Uint8Array, sig: Uint8Array, pubkey: Uint8Array) =>
    verify(sig, msg, pubkey)
}
