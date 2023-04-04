import BN, { ReductionContext } from 'bn.js'
import { utils } from '@noble/ed25519'

export type RedBN = ReturnType<BN['toRed']>

export class FiniteField {
  public readonly r: ReductionContext

  constructor(public readonly red: BN, public readonly en: BN.Endianness) {
    this.r = BN.red(this.red)
  }

  /**
   * Instantination Utility
   */
  static fromString = (red: string, en: BN.Endianness) =>
    new FiniteField(new BN(red), en)
  static fromNumber = (red: number, en: BN.Endianness) =>
    new FiniteField(new BN(red), en)
  static fromBigInt = (red: BigInt, en: BN.Endianness) =>
    FiniteField.fromString(red.toString(), en)

  /**
   * Private encoder/decoder
   */
  encode = (r: ConstructorParameters<typeof BN>[0]): RedBN =>
    new BN(r, 16, this.en).toRed(this.r)
  decode = (r: BN | RedBN, len = 32): Uint8Array =>
    Uint8Array.from(r.toArray(this.en, len))

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
   * Negate a number
   * @param a
   * @returns
   */
  neg = (a: Uint8Array) => this.decode(this.encode(a).redNeg())

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
  inv = (a: Uint8Array) => this.decode(this.encode(a).redInvm())

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
  pow = (a: Uint8Array, b: number) =>
    this.decode(this.encode(a).redPow(new BN(b)))

  /**
   * Compare 2 numbers
   * @param a
   * @param b
   * @returns 0: a=b | 1: a>b | -1: a<b
   */
  equal = (a: Uint8Array, b: Uint8Array) => Buffer.compare(a, b)
}
