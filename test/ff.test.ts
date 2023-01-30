import { CURVE } from '@noble/ed25519'
import { BN } from 'bn.js'
import { expect } from 'chai'
import { FiniteField } from '../dist'

describe('Finite Field', () => {
  const ff = FiniteField.fromBigInt(CURVE.l)
  const a = ff.rand()
  const two = ff.decode(new BN(2))

  it('add/mul', async () => {
    const x = ff.add(a, a)
    const y = ff.mul(a, two)
    expect(ff.equal(x, y)).to.equal(0)
  })

  it('mul/pow', async () => {
    const x = ff.mul(a, a)
    const y = ff.pow(a, two)
    expect(ff.equal(x, y)).to.equal(0)
  })
})
