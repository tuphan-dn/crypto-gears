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
    const _r = this.ff.inv(r)
    const secretSharing = new SecretSharing(this.ff.r, 'be')
    const shares = secretSharing.share(_r, t, n)
    const R = ECTSS.ff.norm(ECCurve.baseMul(r).subarray(1))
    return { shares, R, r: _r }
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
  static addSig = (
    sigs: Uint8Array[],
    H: Uint8Array,
    R: Uint8Array,
    P2: Uint8Array,
    Hr2: Uint8Array,
  ): Uint8Array => {
    const z = sigs.reduce(
      (sum, correctSig) => ECUtil.ff.add(sum, correctSig),
      ECUtil.ff.decode(new BN(0)),
    )
    const H2 = this.ff.pow(H, 2)
    const R2 = this.ff.pow(R, 2)
    const s = ECUtil.ff.mul(
      ECUtil.ff.add(
        ECUtil.ff.add(ECUtil.ff.pow(z, 2), H2),
        ECUtil.ff.neg(ECUtil.ff.add(ECUtil.ff.mul(R2, P2), Hr2)),
      ),
      ECUtil.ff.inv(ECUtil.ff.decode(new BN(2))),
    )
    const sig = new Signature(
      BigInt(ECUtil.ff.encode(R).toString()),
      BigInt(ECUtil.ff.encode(s).toString()),
    )
    return this.finalizeSig(sig)
  }

  /**
   * Partially signs the message by each holder
   * @param R Randomness
   * @param r Shared randomness
   * @param privateKey Private key
   * @returns
   */
  static sign = (
    // Public
    R: Uint8Array,
    // Private
    r: Uint8Array,
    privateKey: Uint8Array,
  ) => {
    if (r.length !== ECUtil.randomnessLength)
      throw new Error('bad randomness size')
    if (privateKey.length !== ECTSS.privateKeyLength)
      throw new Error('bad private key size')

    return this.ff.add(r, this.ff.mul(R, privateKey))
  }

  /**
   * Verify the message.
   * It's identical to the secp256k1 verification.
   */
  static verify = (msg: Uint8Array, sig: Uint8Array, pubkey: Uint8Array) =>
    verify(sig, msg, pubkey, { strict: false })
}
