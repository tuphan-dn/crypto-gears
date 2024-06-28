import { FBN, FiniteField } from './fbn'

export class Poly {
  constructor(public readonly coefficients: FBN[]) {}

  static rand = (ff: FiniteField, order: number) => {
    if (order <= 0)
      throw new Error('The polynomial order must be greater than or equal to 1')
    const coefficients = Array.from(new Array(order).keys()).map(ff.rand)
    return new Poly(coefficients)
  }

  y = (x: FBN) => {
    return this.coefficients.reduce(
      (sum, co, i) => x.pow(i).mul(co).add(sum),
      x.ff.ZERO,
    )
  }
}
