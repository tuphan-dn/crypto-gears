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

/**
 * ECCurve
 */
export class ECCurve {
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
    const z = this.ff.inv(r)
    const secretSharing = new SecretSharing(this.ff.r, 'be')
    const shares = secretSharing.share(z, t, n)
    const R = ECCurve.baseMul(r)
    return { shares, R, z }
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
    return sig.toCompactRawBytes()
  }

  static recoveryBit = (R: Uint8Array, sig: Signature) => {
    const q = Point.fromHex(R)
    let recovery = (q.x === sig.r ? 0 : 2) | Number(q.y & BigInt(1))
    if (sig.hasHighS()) {
      sig = sig.normalizeS()
      recovery ^= 1
    }
    return recovery
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
    Hz2: Uint8Array,
  ): [Uint8Array, number] => {
    const Rx = ECTSS.ff.norm(R.subarray(1))
    const y = sigs.reduce(
      (sum, correctSig) => ECUtil.ff.add(sum, correctSig),
      ECUtil.ff.decode(new BN(0)),
    )
    const H2 = this.ff.pow(H, 2)
    const R2 = this.ff.pow(Rx, 2)
    const s = ECUtil.ff.mul(
      ECUtil.ff.add(
        ECUtil.ff.add(ECUtil.ff.pow(y, 2), H2),
        ECUtil.ff.neg(ECUtil.ff.add(ECUtil.ff.mul(R2, P2), Hz2)),
      ),
      ECUtil.ff.inv(ECUtil.ff.decode(new BN(2))),
    )
    const sig = new Signature(
      BigInt(ECUtil.ff.encode(Rx).toString()),
      BigInt(ECUtil.ff.encode(s).toString()),
    )
    const recovery = this.recoveryBit(R, sig)
    return [this.finalizeSig(sig), recovery]
  }

  /**
   * Partially signs the message by each holder
   * @param R Randomness
   * @param z Shared inversed randomness
   * @param privateKey Private key
   * @returns
   */
  static sign = (
    // Public
    R: Uint8Array,
    // Private
    z: Uint8Array,
    privateKey: Uint8Array,
  ) => {
    if (z.length !== ECUtil.randomnessLength)
      throw new Error('bad randomness size')
    if (privateKey.length !== ECTSS.privateKeyLength)
      throw new Error('bad private key size')

    const Rx = ECTSS.ff.norm(R.subarray(1))
    return this.ff.add(z, this.ff.mul(Rx, privateKey))
  }

  /**
   * Verify the message.
   * It's identical to the secp256k1 verification.
   */
  static verify = (msg: Uint8Array, sig: Uint8Array, pubkey: Uint8Array) =>
    verify(sig, msg, pubkey, { strict: false })
}
