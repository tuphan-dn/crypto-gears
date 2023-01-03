import { CURVE, Point, sync, utils, sign } from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha512'
import BN from 'bn.js'
import { SecretSharing } from './sss'
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
  static randomnessLength = 32
  static derivedKeyLength = 32

  static shareRandomness = (t: number, n: number) => {
    const r = EdCurve.mod(utils.randomBytes(EdUtil.randomnessLength))
    const secretSharing = new SecretSharing(EdCurve.red)
    const shares = secretSharing.share(r, t, n)
    const R = EdCurve.baseMul(r)
    return { shares, R }
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
   * Add partial signatures
   * @param sigs Partial signatures
   * @returns
   */
  static addSig = (...sigs: Uint8Array[]): Uint8Array => {
    for (const sig of sigs)
      if (sig.length !== EdTSS.signatureLength)
        throw new Error('Invalid signature length')
    const rs = sigs.map((sig) => sig.subarray(0, 32))
    const ss = sigs.map((sig) => sig.subarray(32))
    // Compute R
    const R = rs.reduce(
      (sum, r) => EdCurve.addPoint(sum, r),
      Point.ZERO.toRawBytes(),
    )
    // Compute s
    const S = EdCurve.decode(
      ss.reduce(
        (sum, s) => sum.redAdd(EdCurve.encode(s)),
        new BN(0).toRed(EdCurve.red),
      ),
      32,
    )
    // Concat
    return utils.concatBytes(R, S)
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
