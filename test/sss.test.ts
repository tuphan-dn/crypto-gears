import { expect } from 'chai'
import { encode } from 'bs58'
import { alice, print } from './utils'
import { SecretSharing, EdCurve, EdUtil } from '../dist'

describe('Threshold Signature Scheme', function () {
  const secretSharing = new SecretSharing(EdCurve.red)
  const derivedKey = EdUtil.getDerivedKey(alice.secretKey)

  before(() => {
    print('Alice Derived Key:', encode(derivedKey))
  })

  it('2-out-of-2 share/reconstruct', async () => {
    const shares = secretSharing.share(derivedKey, 2, 2)
    const key = secretSharing.construct(shares)
    const sharedKey = Buffer.from(derivedKey).toString('hex')
    const constructedKey = Buffer.from(key).toString('hex')
    expect(constructedKey).equals(sharedKey)
  })

  it('2-out-of-3 share/reconstruct', async () => {
    const shares = secretSharing.share(derivedKey, 2, 3)
    const key = secretSharing.construct(shares.filter((_, i) => i !== 1))
    const sharedKey = Buffer.from(derivedKey).toString('hex')
    const constructedKey = Buffer.from(key).toString('hex')
    expect(constructedKey).equals(sharedKey)
  })

  it('2-out-of-4 share/reconstruct', async () => {
    const shares = secretSharing.share(derivedKey, 2, 4)
    const key = secretSharing.construct(
      shares.filter((_, i) => i !== 0 && i !== 1),
    )
    const sharedKey = Buffer.from(derivedKey).toString('hex')
    const constructedKey = Buffer.from(key).toString('hex')
    expect(constructedKey).equals(sharedKey)
  })

  it('3-out-of-4 share/reconstruct', async () => {
    const shares = secretSharing.share(derivedKey, 2, 4)
    const key = secretSharing.construct(shares.filter((_, i) => i !== 0))
    const sharedKey = Buffer.from(derivedKey).toString('hex')
    const constructedKey = Buffer.from(key).toString('hex')
    expect(constructedKey).equals(sharedKey)
  })

  it('2-out-of-5 share/reconstruct', async () => {
    const shares = secretSharing.share(derivedKey, 2, 4)
    const key = secretSharing.construct(shares.filter((_, i) => i !== 0))
    const sharedKey = Buffer.from(derivedKey).toString('hex')
    const constructedKey = Buffer.from(key).toString('hex')
    expect(constructedKey).equals(sharedKey)
  })
})
