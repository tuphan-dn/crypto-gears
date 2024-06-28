import { ed25519 } from '@noble/curves/ed25519'
import { expect } from 'chai'
import { FiniteField } from '../dist'

describe('Finite Field in LE', () => {
  const ff = new FiniteField(ed25519.CURVE.n, 'le')
  const a = ff.rand()
  const b = ff.rand()
  const two = ff.norm(2)

  it('add/neg', async () => {
    const x = a.add(b)
    const y = b.neg().add(x)
    expect(a.eq(y)).to.true
  })

  it('mul/inv', async () => {
    const x = a.mul(b)
    const y = b.inv().mul(x)
    expect(a.eq(y)).to.true
  })

  it('add/mul', async () => {
    const x = a.add(a)
    const y = a.mul(two)
    expect(x.eq(y)).to.true
  })

  it('mul/pow', async () => {
    const x = a.mul(a)
    const y = a.pow(2)
    expect(x.eq(y)).to.true
  })
})

describe('Finite Field in BE', () => {
  const ff = new FiniteField(ed25519.CURVE.n, 'be')
  const a = ff.rand()
  const b = ff.rand()
  const two = ff.norm(2)

  it('add/neg', async () => {
    const x = a.add(b)
    const y = b.neg().add(x)
    expect(a.eq(y)).to.true
  })

  it('mul/inv', async () => {
    const x = a.mul(b)
    const y = b.inv().mul(x)
    expect(a.eq(y)).to.true
  })

  it('add/mul', async () => {
    const x = a.add(a)
    const y = a.mul(two)
    expect(x.eq(y)).to.true
  })

  it('mul/pow', async () => {
    const x = a.mul(a)
    const y = a.pow(2)
    expect(x.eq(y)).to.true
  })
})
