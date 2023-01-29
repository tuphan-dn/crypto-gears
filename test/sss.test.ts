import { expect } from 'chai'
import { encode } from 'bs58'
import { master, print } from './utils'
import { SecretSharing, EdCurve, EdUtil } from '../dist'
import { utils } from '@noble/ed25519'
import BN from 'bn.js'

describe('Threshold Signature Scheme', function () {
  const secretSharing = new SecretSharing(EdCurve.red, 'le')
  const derivedKey = EdUtil.getDerivedKey(master.secretKey)

  before(() => {
    print('Master Derived Key:', encode(derivedKey))
  })

  it('2-out-of-2 share/reconstruct', async () => {
    const shares = secretSharing.share(derivedKey, 2, 2)
    const key = secretSharing.construct(shares)
    expect(key).to.deep.equals(derivedKey)
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
    const shares = secretSharing.share(derivedKey, 3, 4)
    const key = secretSharing.construct(shares.filter((_, i) => i !== 3))
    const sharedKey = Buffer.from(derivedKey).toString('hex')
    const constructedKey = Buffer.from(key).toString('hex')
    expect(constructedKey).equals(sharedKey)
  })

  it('2-out-of-5 share/reconstruct', async () => {
    const shares = secretSharing.share(derivedKey, 2, 5)
    const key = secretSharing.construct(
      shares.filter((_, i) => i === 0 || i === 4),
    )
    const sharedKey = Buffer.from(derivedKey).toString('hex')
    const constructedKey = Buffer.from(key).toString('hex')
    expect(constructedKey).equals(sharedKey)
  })

  it('additive homomorphism (2-out-of-3)', async () => {
    const a = EdCurve.encode(utils.randomBytes(32))
    const b = EdCurve.encode(utils.randomBytes(32))
    const c = EdCurve.decode(a.redAdd(b), 32)
    const as = secretSharing.share(EdCurve.decode(a, 32), 2, 3)
    const bs = secretSharing.share(EdCurve.decode(b, 32), 2, 3)
    const cs = as
      .filter((_, i) => i !== 2)
      .map((_, i) => {
        const x = EdCurve.encode(as[i].subarray(32))
        const y = EdCurve.encode(bs[i].subarray(32))
        const z = EdCurve.decode(x.redAdd(y), 32)
        return utils.concatBytes(as[i].subarray(0, 32), z)
      })
    const _c = secretSharing.construct(cs)
    expect(c).deep.equals(_c)
  })

  // it('multiplicative homomorphism (2-out-of-3)', async () => {
  //   const a = EdCurve.encode(utils.randomBytes(32))
  //   const b = EdCurve.encode(utils.randomBytes(32))
  //   const c = EdCurve.decode(a.redInvm().redMul(b), 32)
  //   const as = secretSharing.share(EdCurve.decode(a, 32), 2, 3)
  //   const bs = secretSharing.share(EdCurve.decode(b, 32), 2, 3)
  //   const indice = [1, 2, 3].map((i) => new BN(i).toArrayLike(Buffer, 'be', 8))
  //   const pi = secretSharing.pi(indice)
  //   const abs = pi.map((p, i) => {
  //     const x = EdCurve.encode(as[i].subarray(32))
  //     const y = EdCurve.encode(bs[i].subarray(32))
  //     return utils.concatBytes(
  //       as[i].subarray(0, 32),
  //       EdCurve.decode(x.redInvm().redMul(y), 32),
  //     )
  //   })
  //   const _c = secretSharing.construct(abs)
  //   expect(c).deep.equals(_c)
  // })
})
