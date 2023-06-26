import { CURVE, Point, utils, Signature, getPublicKey } from '@noble/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3'
import BN from 'bn.js'
import { SecretSharing } from './sss'
import { FiniteField } from './ff'
import { concatBytes } from '@noble/hashes/utils'
import { equal } from './utils'

/**
 * ECCurve
 */
export class ECCurve {
  static ff = FiniteField.fromBigInt(CURVE.n, 'be')
  static ZERO = Point.ZERO.toRawBytes(true)

  static validate = (point: Uint8Array): boolean => {
    try {
      Point.fromHex(point)
      return true
    } catch (er) {
      return false
    }
  }

  static baseMul = (r: Uint8Array): Uint8Array => {
    if (this.ff.ZERO.eq(this.ff.encode(r))) return Point.ZERO.toRawBytes(true)
    const b = BigInt(new BN(r, 16, this.ff.en).toString())
    return Point.BASE.multiply(b).toRawBytes(true)
  }

  static negPoint = (point: Uint8Array) => {
    const a = Point.fromHex(point)
    return a.negate().toRawBytes()
  }

  static addPoint = (pointA: Uint8Array, pointB: Uint8Array): Uint8Array => {
    if (equal([pointA, Point.ZERO.toRawBytes(true)])) return pointB
    if (equal([pointB, Point.ZERO.toRawBytes(true)])) return pointA
    const a = Point.fromHex(pointA)
    const b = Point.fromHex(pointB)
    return a.add(b).toRawBytes(true)
  }

  static mulScalar = (point: Uint8Array, scalar: Uint8Array): Uint8Array => {
    if (
      equal([point, Point.ZERO.toRawBytes(true)]) ||
      this.ff.ZERO.eq(this.ff.encode(scalar))
    )
      return Point.ZERO.toRawBytes(true)
    const p = Point.fromHex(point)
    const s = BigInt(new BN(scalar, 16, this.ff.en).toString())
    return p.multiply(s).toRawBytes(true)
  }

  static getDerivedKey = (privateKey: Uint8Array) => {
    return this.ff.norm(privateKey)
  }

  static getPublicKey = (privateKey: Uint8Array, derived = false) => {
    if (!derived) privateKey = this.getDerivedKey(privateKey)
    return getPublicKey(privateKey, true)
  }
}

/**
 * ECTSS
 */
export class ECTSS {
  static ff = FiniteField.fromBigInt(CURVE.n, 'be')
  static signatureLength = 65
  static randomnessLength = 32
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

  static shareRandomness = (
    t: number,
    n: number,
    indice: Uint8Array[],
    seed?: Uint8Array,
  ) => {
    const r = this.ff.norm(
      !seed ? utils.randomBytes(this.randomnessLength) : keccak_256(seed),
    )
    const x = this.ff.norm(keccak_256(r))
    const secretSharing = new SecretSharing(this.ff)
    const { shares, zkp } = secretSharing.share(x, t, n, {
      indice,
      ec: ECCurve,
    })
    const R = ECCurve.baseMul(r)
    return { shares, R, r, zkp }
  }

  /**
   * Add partial signatures
   * @param sigs Partial signatures
   * @returns
   */
  static addSig = (sigs: Uint8Array[], r: Uint8Array): [Uint8Array, number] => {
    const x = this.ff.norm(keccak_256(r))
    const [R] = sigs.map((sig) => sig.subarray(0, 33))
    const Rx = this.ff.norm(R.subarray(1))
    const ss = sigs.map((sig) => sig.subarray(33))
    // Compute S
    const S = this.ff.mul(
      this.ff.inv(r),
      this.ff.sub(
        ss.reduce(
          (sum, s) => this.ff.add(sum, s),
          this.ff.decode(this.ff.ZERO),
        ),
        x,
      ),
    )
    const sig = new Signature(
      BigInt(this.ff.encode(Rx).toString()),
      BigInt(this.ff.encode(S).toString()),
    )
    const recovery = this.recoveryBit(R, sig)
    return [this.finalizeSig(sig), recovery]
  }

  /**
   * Partially signs the message by each holder
   * @param h The message hash
   * @param R Encrypted randomness
   * @param x Shared randomness
   * @param derivedKey Derived key
   * @returns
   */
  static sign = (
    // Public
    h: Uint8Array,
    R: Uint8Array,
    // Private
    x: Uint8Array,
    derivedKey: Uint8Array,
  ) => {
    if (x.length !== this.randomnessLength)
      throw new Error('bad randomness size')
    if (derivedKey.length !== this.privateKeyLength)
      throw new Error('bad private key size')

    const Rx = this.ff.norm(R.subarray(1))
    // [e] = [x] + h + Rx * [priv]
    const e = this.ff.add(this.ff.add(h, this.ff.mul(Rx, derivedKey)), x)
    return concatBytes(R, e)
  }

  /**
   * Verify the commitment by zkp
   * @param msg Message
   * @param index Signer id
   * @param pzkp The zk proof of the private key
   * @param xzkp The zk proof of the randomness
   */
  static verify = (
    // Public
    h: Uint8Array,
    R: Uint8Array,
    index: Uint8Array,
    // Witness
    sig: Uint8Array,
    pzkp: Uint8Array[],
    xzkp: Uint8Array[],
  ) => {
    if (pzkp.length !== xzkp.length) throw new Error('bad proofs size')

    const x = this.ff.decode(new BN(index, 8, this.ff.en))
    // sig = R || [e]
    const rG = sig.subarray(0, this.publicKeyLength)
    const e = sig.subarray(this.publicKeyLength, this.signatureLength)
    if (!equal([R, rG])) return false
    // xG, H, Rx
    const xG = xzkp.reduce((sum, co, i) => {
      const t = ECCurve.mulScalar(co, this.ff.pow(x, i))
      if (!sum) return t
      return ECCurve.addPoint(sum, t)
    }, undefined)
    const H = ECCurve.baseMul(this.ff.norm(h))
    const Rx = this.ff.norm(R.subarray(1))
    // [e]G = ([x] + h + Rx * [priv])G = [x]G + hG + Rx * [priv]G
    // where
    // [x]G = (xzkp[0] + xzkp[1] * index + xzkp[2] * index^2 + ...)
    // [priv]G =  Rx * (pzkp[0] + pzkp[1] * index + pzkp[2] * index^2 + ...)
    const eG = ECCurve.baseMul(e)
    const _eG = ECCurve.addPoint(
      xG,
      ECCurve.addPoint(
        H,
        ECCurve.mulScalar(
          pzkp.reduce((sum, co, i) => {
            const t = ECCurve.mulScalar(co, this.ff.pow(x, i))
            if (!sum) return t
            return ECCurve.addPoint(sum, t)
          }, undefined),
          Rx,
        ),
      ),
    )
    return equal([_eG, eG])
  }
}
