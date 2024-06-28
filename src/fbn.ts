import { randomBytes } from '@noble/hashes/utils'
import BN, { ReductionContext, type Endianness } from 'bn.js'

const SUPPORTED_GROUP_LEN = 32

export type RedBN = ReturnType<BN['toRed']>

export class FiniteField {
  public red: ReductionContext
  constructor(
    red: string | number | bigint | BN,
    public readonly en: Endianness,
  ) {
    this.red = BN.red(new BN(red.toString()))
  }

  /**
   * Constants
   */
  get ZERO() {
    return this.norm(0)
  }
  get ONE() {
    return this.norm(1)
  }

  /**
   * Normalize the value to the finite field
   * @param value
   * @returns
   */
  norm = (
    value: string | number | bigint | BN | Uint8Array,
    len = SUPPORTED_GROUP_LEN,
  ) => {
    if (value instanceof Uint8Array) return new FBN(value, this)
    return new FBN(
      Uint8Array.from(new BN(value.toString()).toArray(this.en, len)),
      this,
    )
  }

  /**
   * Randomize a value in the finite field
   * @returns
   */
  rand = (len = SUPPORTED_GROUP_LEN) => this.norm(randomBytes(len))
}

export class FBN {
  public readonly value: RedBN

  constructor(value: Uint8Array, public readonly ff: FiniteField) {
    this.value = new BN(value, 'hex', this.ff.en).toRed(this.ff.red)
  }

  /**
   * Serde
   */
  serialize = (len = SUPPORTED_GROUP_LEN): Uint8Array =>
    Uint8Array.from(this.value.toArray(this.ff.en, len))
  static deserialize = (
    value: Parameters<FiniteField['norm']>[0],
    red: BN,
    en: Endianness,
  ) => new FiniteField(red, en).norm(value)

  /**
   * Clone
   */
  clone = (a?: RedBN) => this.ff.norm(a || this.value)

  /**
   * Transform
   */
  toString = () => this.value.toString()
  toNumber = () => Number(this.value.toString()) // Careful to overflow
  toBigInt = () => BigInt(this.toString())

  /**
   * Add
   * @param a FBN
   * @returns
   */
  add = (a: FBN) => this.clone(this.value.redAdd(a.value))

  /**
   * Negate
   * @returns
   */
  neg = () => this.clone(this.value.redNeg())

  /**
   * Subtract
   * @param a FBN
   * @returns
   */
  sub = (a: FBN) => this.clone(this.value.redSub(a.value))

  /**
   * Multiply
   * @param a FBN
   * @returns
   */
  mul = (a: FBN) => this.clone(this.value.redMul(a.value))

  /**
   * Inverse
   * @returns
   */
  inv = () => this.clone(this.value.redInvm())

  /**
   * Divide
   * @param a FBN
   * @returns
   */
  div = (a: FBN) => a.inv().mul(this)

  /**
   * Square
   * @returns
   */
  sqr = () => this.clone(this.value.redSqr())

  /**
   * Square root
   * @returns
   */
  sqrt = () => this.clone(this.value.redSqrt())

  /**
   * Power
   * @param b Number
   * @returns
   */
  pow = (a: number) => this.clone(this.value.redPow(new BN(a)))

  /**
   * Compare 2 numbers
   * @param a FBN
   * @returns boolean
   */
  eq = (a: FBN) => this.value.eq(a.value)
}
