import { CURVE, Point, sync, utils, sign } from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha512'
import BN from 'bn.js'
import { CryptoScheme, RedBN } from './types'

/**
 * EdCurve
 */
export class EdCurve {
  static scheme: CryptoScheme = 'eddsa'

  static red = BN.red(new BN(CURVE.l.toString()))

  static encode = (r: Uint8Array): RedBN =>
    new BN(r, 16, 'le').toRed(EdCurve.red)

  static decode = (r: BN, length: number): Uint8Array =>
    r.toArrayLike(Buffer, 'le', length)

  static mod = (r: Uint8Array): Uint8Array =>
    EdCurve.decode(EdCurve.encode(r), r.length)

  static baseMul = (r: Uint8Array): Uint8Array => {
    const bn = EdCurve.encode(r)
    const bi = BigInt(bn.toString())
    return Point.BASE.multiply(bi).toRawBytes()
  }

  static addPoint = (pointA: Uint8Array, pointB: Uint8Array): Uint8Array => {
    const a = Point.fromHex(pointA.subarray(0, 32))
    const b = Point.fromHex(pointB.subarray(0, 32))
    return a.add(b).toRawBytes()
  }

  static mulScalar = (point: Uint8Array, scalar: Uint8Array): Uint8Array => {
    const p = Point.fromHex(point.subarray(0, 32))
    const s = BigInt(EdCurve.encode(scalar).toString())
    return p.multiply(s).toRawBytes()
  }
}

export class EdUtil {
  static randomnessLength = 64
  static derivedKeyLength = 32

  static genRandomness = (num = 1) => {
    const r: Uint8Array[] = []
    for (let i = 0; i < num; i++)
      r.push(EdCurve.mod(utils.randomBytes(EdUtil.randomnessLength)))
    let sum = new BN(0).toRed(EdCurve.red)
    r.forEach((e) => (sum = sum.redAdd(EdCurve.encode(e))))
    const R = EdCurve.baseMul(EdCurve.decode(sum, 32))
    return { r, R }
  }

  static getDerivedKey = (privateKey: Uint8Array) => {
    const derivedKey = sha512(privateKey.subarray(0, 32)).subarray(
      0,
      EdUtil.derivedKeyLength,
    )
    derivedKey[0] &= 248
    derivedKey[31] &= 127
    derivedKey[31] |= 64
    return EdCurve.mod(derivedKey)
  }

  static getPublicKey = (privateKey: Uint8Array) => {
    return sync.getPublicKey(privateKey)
  }

  static sign = (
    msg: Uint8Array,
    privateKey: Uint8Array,
  ): Promise<Uint8Array> => {
    return sign(msg, privateKey)
  }
}

/**
 * EdTSS
 */
export class EdTSS {
  static signatureLength = 64
  static publicKeyLength = 32

  /**
   * Add shared signatures
   * @param aSig
   * @param bSig
   * @returns
   */
  static addSig = (aSig: Uint8Array, bSig: Uint8Array): Uint8Array => {
    if (
      aSig.length !== EdTSS.signatureLength ||
      bSig.length !== EdTSS.signatureLength
    )
      throw new Error('Invalid signature length')
    // Compute R
    const R = EdCurve.addPoint(aSig.subarray(0, 32), bSig.subarray(0, 32))
    // Compute s
    const a = EdCurve.encode(aSig.subarray(32, 64))
    const b = EdCurve.encode(bSig.subarray(32, 64))
    const s = EdCurve.decode(a.redAdd(b), 32)
    // Concat
    const sig = new Uint8Array(EdTSS.signatureLength)
    for (let i = 0; i < 32; i++) {
      sig[i] = R[i]
      sig[32 + i] = s[i]
    }
    return sig
  }

  /**
   * Partially signs the message by each holder
   * @param msg Message
   * @param r Shared randomness
   * @param derivedKey Derived key
   * @param R Randomness
   * @param publicKey Master public key
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
    if (r.length !== EdUtil.randomnessLength)
      throw new Error('bad randomness size')
    if (derivedKey.length !== EdUtil.derivedKeyLength)
      throw new Error('bad derived key size')
    if (publicKey.length !== EdTSS.publicKeyLength)
      throw new Error('bad public key size')

    const n = msg.length
    const sm = new Uint8Array(64 + n)

    // sm = [R,*,msg]
    for (let i = 0; i < n; i++) sm[64 + i] = msg[i] // Assign M
    for (let i = 0; i < 32; i++) sm[i] = R[i] // Assign R

    // H(R,A,M)
    for (let i = 0; i < 32; i++) sm[32 + i] = publicKey[i] // Assign A
    const h = sha512(sm)
    // s = r + H(R,A,M)a
    const _r = EdCurve.encode(r)
    const _h = EdCurve.encode(h)
    const _a = EdCurve.encode(derivedKey)
    const s = EdCurve.decode(_h.redMul(_a).redAdd(_r), 32)

    // sm = [R,s,msg]
    for (let i = 0; i < 32; i++) sm[32 + i] = s[i]

    // sm = [rG,s,msg]
    const rG = EdCurve.baseMul(r)
    for (let i = 0; i < 32; i++) sm[i] = rG[i]

    return sm.subarray(0, EdTSS.signatureLength)
  }

  /**
   * Verify the message.
   * It's identical to the ed25519 verification.
   */
  static verify = (msg: Uint8Array, sig: Uint8Array, pubkey: Uint8Array) =>
    sync.verify(sig, msg, pubkey)
}
