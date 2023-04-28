import { randomBytes } from '@noble/hashes/utils'
import { EdCurve } from './edtss'

export const xor = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  if (a.length !== b.length) throw new Error('Invalid buffer length')
  const c = new Uint8Array(a.length)
  for (let i = 0; i < a.length; i++) c[i] = a[i] ^ b[i]
  return c
}

export const parity = (a: Uint8Array) => {
  let b = a.reduce((x, y) => x ^ y, 0)
  b = b ^ (b >> 1)
  b = b ^ (b >> 2)
  b = b ^ (b >> 4)
  return b & 1
}

/**
 * This specific lib to encrypt/decrypt arbitrary fixed-length 32-bytes data.
 * If you would like to encrypt arbitrary message lengths, let's try ExtendedElgamal
 */

export class ElGamal {
  static publicKeyLength = 32
  static privateKeyLength = 32
  static plainTextLength = 32
  static cipherTextLength = 64

  encrypt = (msg: Uint8Array, pubkey: Uint8Array): Uint8Array => {
    if (msg.length != ElGamal.plainTextLength)
      throw new Error(
        `Invalid block length. It must be 30 bytes instead of ${msg.length} bytes.`,
      )
    const r = EdCurve.ff.rand()
    const R = EdCurve.baseMul(r)
    const m = xor(msg, R)
    if (EdCurve.ff.equal(m, EdCurve.ff.norm(m)) !== 0)
      return this.encrypt(msg, pubkey)
    const s = EdCurve.mulScalar(pubkey, r)
    const c = EdCurve.ff.add(m, s)
    return new Uint8Array([...R, ...c])
  }

  decrypt = (cipher: Uint8Array, privkey: Uint8Array): Uint8Array => {
    if (privkey.length !== ElGamal.privateKeyLength)
      throw new Error('Invalid private key length')
    if (cipher.length !== ElGamal.cipherTextLength)
      throw new Error('Invalid cipher text length')
    const priv = EdCurve.getDerivedKey(privkey)
    const R = cipher.subarray(0, 32)
    const c = cipher.subarray(32, ElGamal.cipherTextLength)
    const s = EdCurve.mulScalar(R, priv)
    const m = EdCurve.ff.sub(c, s)
    const msg = xor(m, R)
    return msg
  }
}

/**
 * ONLY SUPPORT ED25519
 * The encryption is block stream. Each block has length of 32.
 * The first byte is to bit parity
 * The second byte is to length
 * The rest 30 bytes is to message
 *
 * Note that the lib isn't time-optimized. So it must be available to short message.
 */
export class ExtendedElGamal {
  static publicKeyLength = 32
  static privateKeyLength = 32
  static blockLength = 32
  static plainTextLength = 30
  static cipherTextLength = 64

  constructor() {}

  private _enc = (msg: Uint8Array, pubkey: Uint8Array): Uint8Array => {
    const length = msg.length
    if (length > ExtendedElGamal.plainTextLength)
      throw new Error(
        `Invalid block length. It must be 30 bytes instead of ${length} bytes.`,
      )
    const par = parity(msg)
    const padding = randomBytes(ExtendedElGamal.plainTextLength - length)
    const m = new Uint8Array([par, length, ...padding, ...msg])
    const r = EdCurve.ff.rand()
    const R = EdCurve.baseMul(r)
    const s = EdCurve.mulScalar(pubkey, r)
    const c = xor(m, s)
    return new Uint8Array([...R, ...c])
  }

  private _dec = (cipher: Uint8Array, privkey: Uint8Array): Uint8Array => {
    if (privkey.length !== ExtendedElGamal.privateKeyLength)
      throw new Error('Invalid private key length')
    if (cipher.length % ExtendedElGamal.cipherTextLength !== 0)
      throw new Error('Invalid cipher text length')
    const R = cipher.subarray(0, 32)
    const c = cipher.subarray(32, ExtendedElGamal.cipherTextLength)
    const s = EdCurve.mulScalar(R, privkey)
    const p = xor(c, s)
    const par = p[0]
    const length = p[1]
    const msg = p.subarray(
      ExtendedElGamal.blockLength - length,
      ExtendedElGamal.blockLength,
    )
    if (par !== parity(msg)) throw new Error('Incorrect cipher text')
    return msg
  }

  encrypt = (m: Uint8Array, pubkey: Uint8Array) => {
    let c = []
    let offset = 0
    while (offset < m.length) {
      c.push([
        ...this._enc(
          m.subarray(offset, offset + ExtendedElGamal.plainTextLength),
          pubkey,
        ),
      ])
      offset = offset + ExtendedElGamal.plainTextLength
    }
    return new Uint8Array(c.flat())
  }

  decrypt = (c: Uint8Array, privkey: Uint8Array): Uint8Array => {
    const priv = EdCurve.getDerivedKey(privkey)
    let m = []
    let offset = 0
    while (offset < c.length) {
      m.push([
        ...this._dec(
          c.subarray(offset, offset + ExtendedElGamal.cipherTextLength),
          priv,
        ),
      ])
      offset = offset + ExtendedElGamal.cipherTextLength
    }
    return new Uint8Array(m.flat())
  }
}
