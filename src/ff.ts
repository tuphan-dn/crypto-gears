import BN, { ReductionContext } from 'bn.js'
import { utils } from '@noble/ed25519'

export type RedBN = ReturnType<BN['toRed']>

export class FiniteField {
  private readonly r: ReductionContext

  constructor(public readonly red: BN) {
    this.r = BN.red(this.red)
  }

  /**
   * Instantination Utility
   */
  static fromString = (red: string) => new FiniteField(new BN(red))
  static fromNumber = (red: number) => new FiniteField(new BN(red))
  static fromBigInt = (red: BigInt) => FiniteField.fromString(red.toString())

  /**
   * Private encoder/decoder
   */
  encode = (r: Uint8Array): RedBN => new BN(r, 16, 'le').toRed(this.r)
  decode = (r: BN, len = 32): Uint8Array => r.toArrayLike(Buffer, 'le', len)

  /**
   * Normalize or Modularize
   * @param a
   * @returns
   */
  norm = (a: Uint8Array) => this.decode(this.encode(a), a.length)

  /**
   * Randomize
   * @returns
   */
  rand = () => this.norm(utils.randomBytes(32))

  /**
   * Add 2 numbers
   * @param a
   * @param b
   * @returns
   */
  add = (a: Uint8Array, b: Uint8Array) =>
    this.decode(this.encode(a).redAdd(this.encode(b)))

  /**
   * Multiply 2 numbers
   * @param a
   * @param b
   * @returns
   */
  mul = (a: Uint8Array, b: Uint8Array) =>
    this.decode(this.encode(a).redMul(this.encode(b)))

  /**
   * Inverse a number
   * @param a
   * @returns
   */
  ivm = (a: Uint8Array) => this.decode(this.encode(a).redInvm())

  /**
   * Square a number
   * @param a
   * @returns
   */
  sqr = (a: Uint8Array) => this.decode(this.encode(a).redSqr())

  /**
   * Square root of a number
   * @param a
   * @returns
   */
  sqrt = (a: Uint8Array) => this.decode(this.encode(a).redSqrt())

  /**
   * To the power of a number
   * @param a
   * @param b
   * @returns
   */
  pow = (a: Uint8Array, b: Uint8Array) =>
    this.decode(this.encode(a).redPow(this.encode(b)))

  /**
   * Compare 2 numbers
   * @param a
   * @param b
   * @returns 0: a=b; 1: a>b; -1: a<b
   */
  equal = (a: Uint8Array, b: Uint8Array) => Buffer.compare(a, b)
}
