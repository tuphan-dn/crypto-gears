import { expect } from 'chai'
import { encode } from 'bs58'
import { getDerivedKey } from '../src/tss.utils'
import { share, construct } from '../src/sss'
import { alice, print } from './utils'

describe('Threshold Signature Scheme', function () {
  const derivedKey = getDerivedKey(alice.secretKey)

  before(() => {
    print('Alice Derived Key:', encode(derivedKey))
  })

  it('2-out-of-2 share/reconstruct', async () => {
    const shares = share(derivedKey, 2, 2)
    const key = construct(shares.filter((_, i) => i !== 0))
    const sharedKey = Buffer.from(derivedKey).toString('hex')
    const constructedKey = Buffer.from(key).toString('hex')
    expect(constructedKey).equals(sharedKey)
  })

  it('2-out-of-3 share/reconstruct', async () => {
    const shares = share(derivedKey, 2, 3)
    const key = construct(shares.filter((_, i) => i !== 0))
    const sharedKey = Buffer.from(derivedKey).toString('hex')
    const constructedKey = Buffer.from(key).toString('hex')
    expect(constructedKey).equals(sharedKey)
  })

  it('2-out-of-4 share/reconstruct', async () => {
    const shares = share(derivedKey, 2, 4)
    const key = construct(shares.filter((_, i) => i !== 0))
    const sharedKey = Buffer.from(derivedKey).toString('hex')
    const constructedKey = Buffer.from(key).toString('hex')
    expect(constructedKey).equals(sharedKey)
  })

  it('3-out-of-4 share/reconstruct', async () => {
    const shares = share(derivedKey, 2, 4)
    const key = construct(shares.filter((_, i) => i !== 0))
    const sharedKey = Buffer.from(derivedKey).toString('hex')
    const constructedKey = Buffer.from(key).toString('hex')
    expect(constructedKey).equals(sharedKey)
  })

  it('2-out-of-5 share/reconstruct', async () => {
    const shares = share(derivedKey, 2, 4)
    const key = construct(shares.filter((_, i) => i !== 0))
    const sharedKey = Buffer.from(derivedKey).toString('hex')
    const constructedKey = Buffer.from(key).toString('hex')
    expect(constructedKey).equals(sharedKey)
  })
})
