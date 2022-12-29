import { CURVE, Point, getPublicKey, sign } from '@noble/secp256k1'
import BN from 'bn.js'
import { RedBN } from './types'

/**
 * ECCurve
 */
export class ECCurve {
  static code = 'ecdsa'

  static red = BN.red(new BN(CURVE.P.toString()))

  static encode = (r: Uint8Array): RedBN =>
    new BN(r, 16, 'le').toRed(ECCurve.red)

  static decode = (r: BN, length: number): Uint8Array =>
    r.toArrayLike(Buffer, 'le', length)

  static mod = (r: Uint8Array): Uint8Array =>
    new BN(r, 16, 'le').toRed(ECCurve.red).toArrayLike(Buffer, 'le', r.length)

  static baseMul = (r: Uint8Array): Uint8Array => {
    const bn = new BN(r, 16, 'le')
    const bi = BigInt(bn.toString())
    return Point.BASE.multiply(bi).toRawBytes()
  }

  static addPoint = (aPubkey: Uint8Array, bPubkey: Uint8Array): Uint8Array => {
    const a = Point.fromHex(aPubkey.subarray(0, 32))
    const b = Point.fromHex(bPubkey.subarray(0, 32))
    return a.add(b).toRawBytes()
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
