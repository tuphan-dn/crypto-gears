import { utils } from '@noble/ed25519'
import type { ECCurve } from './ectss'
import type { EdCurve } from './edtss'

/**
 * The encryption is block stream. Each block has length of 32.
 * The first byte is to bit parity
 * The second byte is to length
 * The rest 30 bytes is to message
 *
 * This lib only supports EdDSA.
 * This lib is not time-optimized. So it must be available to short message.
 */
export class ElGamal {
  static publicKeyLength = 32
  static privateKeyLength = 32
  static blockLength = 32
  static plainTextLength = 30
  static cipherTextLength = 64

  constructor(public readonly curve: typeof ECCurve | typeof EdCurve) {}

  /**
   * Remove the recovery bit in case of secp256k1
   * @param s The compressed point
   * @returns Trimmed `s`
   */
  static trim = (s: Uint8Array) => {
    const offset = s.length - ElGamal.publicKeyLength
    if (offset < 0) throw new Error('Invalid public key length')
    return s.subarray(offset)
  }

  static xor = (a: Uint8Array, b: Uint8Array): Uint8Array => {
    if (a.length !== b.length) throw new Error('Invalid buffer length')
    const c = new Uint8Array(a.length)
    for (let i = 0; i < a.length; i++) c[i] = a[i] ^ b[i]
    return c
  }

  static parity = (a: Uint8Array) => {
    let b = a.reduce((x, y) => x ^ y, 0)
    b = b ^ (b >> 1)
    b = b ^ (b >> 2)
    b = b ^ (b >> 4)
    return b & 1
  }

  private _enc = (msg: Uint8Array, pubkey: Uint8Array): Uint8Array => {
    const length = msg.length
    if (length > ElGamal.plainTextLength)
      throw new Error(
        `Invalid block length. It must be 30 bytes instead of ${length} bytes.`,
      )
    const parity = ElGamal.parity(msg)
    const padding = utils.randomBytes(ElGamal.plainTextLength - length)
    const m =
      this.curve.ff.en === 'le'
        ? new Uint8Array([parity, length, ...padding, ...msg])
        : new Uint8Array([...msg, ...padding, length, parity])
    const r = this.curve.ff.norm(utils.randomBytes(32))
    const R = ElGamal.trim(this.curve.baseMul(r))
    const s = ElGamal.trim(this.curve.mulScalar(pubkey, r))
    const c = ElGamal.xor(m, s)
    return new Uint8Array([...R, ...c])
  }

  private _dec = (cipher: Uint8Array, privkey: Uint8Array): Uint8Array => {
    if (privkey.length !== ElGamal.privateKeyLength)
      throw new Error('Invalid private key length')
    if (cipher.length % ElGamal.cipherTextLength !== 0)
      throw new Error('Invalid cipher text length')
    const R = cipher.subarray(0, 32)
    const c = cipher.subarray(32, ElGamal.cipherTextLength)
    const s = ElGamal.trim(this.curve.mulScalar(R, privkey))
    const p = ElGamal.xor(c, s)
    const [parity, length] =
      this.curve.ff.en === 'le'
        ? [p[0], p[1]]
        : [p[ElGamal.blockLength - 1], p[ElGamal.blockLength - 2]]
    const msg =
      this.curve.ff.en === 'le'
        ? p.subarray(ElGamal.blockLength - length, ElGamal.blockLength)
        : p.subarray(0, length)
    if (parity !== ElGamal.parity(msg)) throw new Error('Incorrect cipher text')
    return msg
  }

  encrypt = (m: Uint8Array, pubkey: Uint8Array) => {
    let c = []
    let offset = 0
    while (offset < m.length) {
      c.push([
        ...this._enc(
          m.subarray(offset, offset + ElGamal.plainTextLength),
          pubkey,
        ),
      ])
      offset = offset + ElGamal.plainTextLength
    }
    return new Uint8Array(c.flat())
  }

  decrypt = async (c: Uint8Array, privkey: Uint8Array): Promise<Uint8Array> => {
    const priv = this.curve.getDerivedKey(privkey)
    let m = []
    let offset = 0
    while (offset < c.length) {
      m.push([
        ...this._dec(
          c.subarray(offset, offset + ElGamal.cipherTextLength),
          priv,
        ),
      ])
      offset = offset + ElGamal.cipherTextLength
    }
    return new Uint8Array(m.flat())
  }
}
