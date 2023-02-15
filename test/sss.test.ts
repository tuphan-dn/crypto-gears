import { expect } from 'chai'
import { SecretSharing, EdCurve, EdUtil, ECCurve, ECUtil } from '../dist'
import { utils } from '@noble/ed25519'

describe('Threshold Signature Scheme in LE', function () {
  const secretSharing = new SecretSharing(EdCurve.ff.r, 'le')
  const r = EdUtil.ff.norm(EdUtil.ff.rand())

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

  it('2-out-of-5 share/reconstruct', async () => {
    const shares = secretSharing.share(r, 2, 5)
    const key = secretSharing.construct(
      shares.filter((_, i) => i === 0 || i === 4),
    )
    expect(key).to.deep.equals(r)
  })

  it('additive homomorphism (2-out-of-3)', async () => {
    const a = EdCurve.ff.encode(utils.randomBytes(32))
    const b = EdCurve.ff.encode(utils.randomBytes(32))
    const c = EdCurve.ff.decode(a.redAdd(b), 32)
    const as = secretSharing.share(EdCurve.ff.decode(a, 32), 2, 3)
    const bs = secretSharing.share(EdCurve.ff.decode(b, 32), 2, 3)
    const cs = as
      .filter((_, i) => i !== 2)
      .map((_, i) => {
        const x = EdCurve.ff.encode(as[i].subarray(32))
        const y = EdCurve.ff.encode(bs[i].subarray(32))
        const z = EdCurve.ff.decode(x.redAdd(y), 32)
        return utils.concatBytes(as[i].subarray(0, 32), z)
      })
    const _c = secretSharing.construct(cs)
    expect(c).deep.equals(_c)
  })
})

describe('Threshold Signature Scheme in BE', function () {
  const secretSharing = new SecretSharing(ECCurve.ff.r, 'be')
  const r = ECUtil.ff.norm(ECUtil.ff.rand())

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

  it('2-out-of-5 share/reconstruct', async () => {
    const shares = secretSharing.share(r, 2, 5)
    const key = secretSharing.construct(
      shares.filter((_, i) => i === 0 || i === 4),
    )
    expect(key).to.deep.equals(r)
  })

  it('additive homomorphism (2-out-of-3)', async () => {
    const a = ECCurve.ff.encode(utils.randomBytes(32))
    const b = ECCurve.ff.encode(utils.randomBytes(32))
    const c = ECCurve.ff.decode(a.redAdd(b), 32)
    const as = secretSharing.share(ECCurve.ff.decode(a, 32), 2, 3)
    const bs = secretSharing.share(ECCurve.ff.decode(b, 32), 2, 3)
    const cs = as
      .filter((_, i) => i !== 2)
      .map((_, i) => {
        const x = ECCurve.ff.encode(as[i].subarray(32))
        const y = ECCurve.ff.encode(bs[i].subarray(32))
        const z = ECCurve.ff.decode(x.redAdd(y), 32)
        return utils.concatBytes(as[i].subarray(0, 32), z)
      })
    const _c = secretSharing.construct(cs)
    expect(c).deep.equals(_c)
  })
})
