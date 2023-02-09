import { CURVE } from '@noble/ed25519'
import { BN } from 'bn.js'
import { expect } from 'chai'
import { FiniteField } from '../dist'

describe('Finite Field in LE', () => {
  const ff = FiniteField.fromBigInt(CURVE.l, 'le')
  const a = ff.rand()
  const b = ff.rand()
  const two = ff.decode(new BN(2))

  it('add/neg', async () => {
    const x = ff.add(a, b)
    const y = ff.add(x, ff.neg(b))
    expect(ff.equal(a, y)).to.equal(0)
  })

  it('mul/inv', async () => {
    const x = ff.mul(a, b)
    const y = ff.mul(x, ff.inv(b))
    expect(ff.equal(a, y)).to.equal(0)
  })

  it('add/mul', async () => {
    const x = ff.add(a, a)
    const y = ff.mul(a, two)
    expect(ff.equal(x, y)).to.equal(0)
  })

  it('mul/pow', async () => {
    const x = ff.mul(a, a)
    const y = ff.pow(a, 2)
    expect(ff.equal(x, y)).to.equal(0)
  })
})

describe('Finite Field in BE', () => {
  const ff = FiniteField.fromBigInt(CURVE.l, 'be')
  const a = ff.rand()
  const b = ff.rand()
  const two = ff.decode(new BN(2))

  it('add/neg', async () => {
    const x = ff.add(a, b)
    const y = ff.add(x, ff.neg(b))
    expect(ff.equal(a, y)).to.equal(0)
  })

  it('mul/inv', async () => {
    const x = ff.mul(a, b)
    const y = ff.mul(x, ff.inv(b))
    expect(ff.equal(a, y)).to.equal(0)
  })

  it('add/mul', async () => {
    const x = ff.add(a, a)
    const y = ff.mul(a, two)
    expect(ff.equal(x, y)).to.equal(0)
  })

  it('mul/pow', async () => {
    const x = ff.mul(a, a)
    const y = ff.pow(a, 2)
    expect(ff.equal(x, y)).to.equal(0)
  })
})
