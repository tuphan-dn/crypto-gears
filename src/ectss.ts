import { CURVE, Point, getPublicKey, sign } from '@noble/secp256k1'
import BN from 'bn.js'
import { CryptoScheme, RedBN } from './types'

/**
 * ECCurve
 */
export class ECCurve {
  static scheme: CryptoScheme = 'ecdsa'

  static red = BN.red(new BN(CURVE.P.toString()))

  static encode = (r: Uint8Array): RedBN =>
    new BN(r, 16, 'le').toRed(ECCurve.red)

  static decode = (r: BN, length: number): Uint8Array =>
    r.toArrayLike(Buffer, 'le', length)

  static mod = (r: Uint8Array): Uint8Array =>
    ECCurve.decode(ECCurve.encode(r), r.length)

  static baseMul = (r: Uint8Array): Uint8Array => {
    const bn = ECCurve.encode(r)
    const bi = BigInt(bn.toString())
    return Point.BASE.multiply(bi).toRawBytes(true).subarray(1)
  }

  static addPoint = (pointA: Uint8Array, pointB: Uint8Array): Uint8Array => {
    const a = Point.fromHex(pointA.subarray(0, 32))
    const b = Point.fromHex(pointB.subarray(0, 32))
    return a.add(b).toRawBytes(true).subarray(1)
  }

  static mulScalar = (point: Uint8Array, scalar: Uint8Array): Uint8Array => {
    const p = Point.fromHex(point.subarray(0, 32))
    const s = BigInt(ECCurve.encode(scalar).toString())
    return p.multiply(s).toRawBytes(true).subarray(1)
  }
}

export class ECUtil {
  static randomnessLength = 64
  static derivedKeyLength = 32

  static getPublicKey = (privateKey: Uint8Array) => {
    return getPublicKey(privateKey)
  }

  static sign = (
    msg: Uint8Array,
    privateKey: Uint8Array,
  ): Promise<Uint8Array> => {
    return sign(msg, privateKey)
  }
}
