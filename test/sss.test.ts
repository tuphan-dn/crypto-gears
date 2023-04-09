import { expect } from 'chai'
import { SecretSharing, EdTSS, ECTSS } from '../dist'
import { utils } from '@noble/ed25519'

describe('Threshold Signature Scheme in LE', function () {
  const secretSharing = new SecretSharing(EdTSS.ff)
  const r = EdTSS.ff.rand()

  it('1-out-of-1 share/reconstruct', async () => {
    const shares = secretSharing.share(r, 1, 1)
    const key = secretSharing.construct(shares)
    expect(key).to.deep.equals(r)
  })

  it('2-out-of-2 share/reconstruct', async () => {
    const shares = secretSharing.share(r, 2, 2)
    const key = secretSharing.construct(shares)
    expect(key).to.deep.equals(r)
  })

  it('2-out-of-3 share/reconstruct', async () => {
    const shares = secretSharing.share(r, 2, 3)
    const key = secretSharing.construct(shares.filter((_, i) => i !== 1))
    expect(key).to.deep.equals(r)
  })

  it('2-out-of-4 share/reconstruct', async () => {
    const shares = secretSharing.share(r, 2, 4)
    const key = secretSharing.construct(
      shares.filter((_, i) => i !== 0 && i !== 1),
    )
    expect(key).to.deep.equals(r)
  })

  it('3-out-of-4 share/reconstruct', async () => {
    const shares = secretSharing.share(r, 3, 4)
    const key = secretSharing.construct(shares.filter((_, i) => i !== 3))
    expect(key).to.deep.equals(r)
  })

  it('500-out-of-500 share/reconstruct', async () => {
    const shares = secretSharing.share(r, 500, 500)
    const key = secretSharing.construct(shares)
    expect(key).to.deep.equals(r)
  })

  it('additive homomorphism (2-out-of-3)', async () => {
    const a = secretSharing.ff.encode(utils.randomBytes(32))
    const b = secretSharing.ff.encode(utils.randomBytes(32))
    const c = secretSharing.ff.decode(a.redAdd(b), 32)
    const as = secretSharing.share(secretSharing.ff.decode(a, 32), 2, 3)
    const bs = secretSharing.share(secretSharing.ff.decode(b, 32), 2, 3)
    const cs = as
      .filter((_, i) => i !== 2)
      .map((_, i) => {
        const x = secretSharing.ff.encode(as[i].subarray(32))
        const y = secretSharing.ff.encode(bs[i].subarray(32))
        const z = secretSharing.ff.decode(x.redAdd(y), 32)
        return utils.concatBytes(as[i].subarray(0, 32), z)
      })
    const _c = secretSharing.construct(cs)
    expect(c).deep.equals(_c)
  })

  it('proactivate (3-out-of-3)', async () => {
    const shares = secretSharing.share(r, 3, 3)
    const updates = secretSharing.proactivate(3, 3, shares[0].subarray(24, 32))
    const proactiveShares = shares.map((share, i) =>
      secretSharing.merge(share, updates[i]),
    )
    const key = secretSharing.construct(proactiveShares)
    expect(key).to.deep.equals(r)
  })
})

describe('Threshold Signature Scheme in BE', function () {
  const secretSharing = new SecretSharing(ECTSS.ff)
  const r = ECTSS.ff.rand()

  it('1-out-of-1 share/reconstruct', async () => {
    const shares = secretSharing.share(r, 1, 1)
    const key = secretSharing.construct(shares)
    expect(key).to.deep.equals(r)
  })

  it('2-out-of-2 share/reconstruct', async () => {
    const shares = secretSharing.share(r, 2, 2)
    const key = secretSharing.construct(shares)
    expect(key).to.deep.equals(r)
  })

  it('2-out-of-3 share/reconstruct', async () => {
    const shares = secretSharing.share(r, 2, 3)
    const key = secretSharing.construct(shares.filter((_, i) => i !== 1))
    expect(key).to.deep.equals(r)
  })

  it('2-out-of-4 share/reconstruct', async () => {
    const shares = secretSharing.share(r, 2, 4)
    const key = secretSharing.construct(
      shares.filter((_, i) => i !== 0 && i !== 1),
    )
    expect(key).to.deep.equals(r)
  })

  it('3-out-of-4 share/reconstruct', async () => {
    const shares = secretSharing.share(r, 3, 4)
    const key = secretSharing.construct(shares.filter((_, i) => i !== 3))
    expect(key).to.deep.equals(r)
  })

  it('500-out-of-500 share/reconstruct', async () => {
    const shares = secretSharing.share(r, 500, 500)
    const key = secretSharing.construct(shares)
    expect(key).to.deep.equals(r)
  })

  it('additive homomorphism (2-out-of-3)', async () => {
    const a = secretSharing.ff.encode(utils.randomBytes(32))
    const b = secretSharing.ff.encode(utils.randomBytes(32))
    const c = secretSharing.ff.decode(a.redAdd(b), 32)
    const as = secretSharing.share(secretSharing.ff.decode(a, 32), 2, 3)
    const bs = secretSharing.share(secretSharing.ff.decode(b, 32), 2, 3)
    const cs = as
      .filter((_, i) => i !== 2)
      .map((_, i) => {
        const x = secretSharing.ff.encode(as[i].subarray(32))
        const y = secretSharing.ff.encode(bs[i].subarray(32))
        const z = secretSharing.ff.decode(x.redAdd(y), 32)
        return utils.concatBytes(as[i].subarray(0, 32), z)
      })
    const _c = secretSharing.construct(cs)
    expect(c).deep.equals(_c)
  })

  it('proactivate (3-out-of-3)', async () => {
    const shares = secretSharing.share(r, 3, 3)
    const updates = secretSharing.proactivate(3, 3, shares[0].subarray(24, 32))
    const proactiveShares = shares.map((share, i) =>
      secretSharing.merge(share, updates[i]),
    )
    const key = secretSharing.construct(proactiveShares)
    expect(key).to.deep.equals(r)
  })
})
