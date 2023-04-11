import { CURVE, Point, utils, verify } from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha512'
import BN from 'bn.js'
import { SecretSharing } from './sss'
import { FiniteField } from './ff'

/**
 * EdCurve
 */
export class EdCurve {
  static ff = FiniteField.fromBigInt(CURVE.n, 'le')

  static baseMul = (r: Uint8Array) => {
    const b = BigInt(new BN(r, 16, this.ff.en).toString())
    return Point.BASE.multiply(b).toRawBytes()
  }

  static negPoint = (point: Uint8Array) => {
    const a = Point.fromHex(point)
    return a.negate().toRawBytes()
  }

  static addPoint = (pointA: Uint8Array, pointB: Uint8Array) => {
    const a = Point.fromHex(pointA)
    const b = Point.fromHex(pointB)
    return a.add(b).toRawBytes()
  }

  static mulScalar = (point: Uint8Array, scalar: Uint8Array) => {
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
  static ff = FiniteField.fromBigInt(CURVE.l, 'le')
  static signatureLength = 64
  static privateKeyLength = 32
  static publicKeyLength = 32
  static randomnessLength = 32

  static shareRandomness = (t: number, n: number) => {
    const r = this.ff.norm(utils.randomBytes(EdTSS.randomnessLength))
    const secretSharing = new SecretSharing(this.ff)
    const shares = secretSharing.share(r, t, n)
    const R = EdCurve.baseMul(r)
    return { shares, R }
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
    return utils.concatBytes(R, S)
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

    const n = msg.length
    const sm = new Uint8Array(64 + n)

    // sm = [R,*,msg]
    for (let i = 0; i < n; i++) sm[64 + i] = msg[i] // Assign M
    for (let i = 0; i < 32; i++) sm[i] = R[i] // Assign R

    // H(R,A,M)
    for (let i = 0; i < 32; i++) sm[32 + i] = publicKey[i] // Assign A
    const h = sha512(sm)
    // s = r + H(R,A,M)a
    const s = this.ff.add(this.ff.mul(h, derivedKey), r)

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
  static verify = async (
    msg: Uint8Array,
    sig: Uint8Array,
    pubkey: Uint8Array,
  ) => verify(sig, msg, pubkey)
}
