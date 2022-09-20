import BN, { IPrimeName, ReductionContext } from 'bn.js'
import { hash, randomBytes } from 'tweetnacl'

export class DSA {
  private red: ReductionContext
  constructor(public readonly prime: IPrimeName = 'p25519') {
    this.red = BN.red(prime)
  }

  rand = () => {
    const r = hash(randomBytes(32))
    const a = new BN(r)
    const b = a.toRed(this.red)
    return b
  }

  hash = hash

  sign = (m: BN) => {
    const k = this.rand()
  }
}
