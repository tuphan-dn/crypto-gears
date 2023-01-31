import { utils } from '@noble/ed25519'
import { Curve } from './types'

export type CipherText = {
  c: Uint8Array
  R: Uint8Array
}

export class ElGamal {
  constructor(private readonly curve: Curve) {}

  static publicKeyLength = 32
  static privateKeyLength = 32
  static plainTextLength = 32
  static cipherTextLength = 32

  private xor = (a: Uint8Array, b: Uint8Array): Uint8Array => {
    if (
      a.length !== ElGamal.plainTextLength ||
      b.length !== ElGamal.plainTextLength
    )
      throw new Error('Invalid buffer length')
    const c = new Uint8Array(ElGamal.plainTextLength)
    for (let i = 0; i < ElGamal.plainTextLength; i++) c[i] = a[i] ^ b[i]
    return c
  }

  private trim = (s: Uint8Array) => {
    const offset = s.length - ElGamal.publicKeyLength
    if (offset < 0) throw new Error('Invalid public key length')
    return s.length === ElGamal.publicKeyLength ? s : s.subarray(offset)
  }

  encrypt = (m: Uint8Array, pubkey: Uint8Array): CipherText => {
    if (m.length !== ElGamal.plainTextLength)
      throw new Error('Invalid plain text length')
    const r = this.curve.ff.norm(utils.randomBytes(32))
    const R = this.curve.baseMul(r)
    const s = this.curve.mulScalar(pubkey, r)
    const c = this.xor(m, this.trim(s))
    return { c, R }
  }

  decrypt = ({ c, R }: CipherText, privkey: Uint8Array): Uint8Array => {
    if (privkey.length !== ElGamal.privateKeyLength)
      throw new Error('Invalid private key length')
    if (c.length !== ElGamal.cipherTextLength)
      throw new Error('Invalid cipher text length')
    const s = this.curve.mulScalar(R, privkey)
    const p = this.xor(c, this.trim(s))
    return p
  }
}
