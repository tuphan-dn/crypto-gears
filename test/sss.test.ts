import { expect } from 'chai'
import { SecretSharing, EdTSS, ECTSS } from '../dist'
import { concatBytes, randomBytes } from '@noble/hashes/utils'

describe('Threshold Signature Scheme in LE', function () {
  const secretSharing = new SecretSharing(EdTSS.ff)
  const secret = secretSharing.ff.rand()

  it('1-out-of-1 share/reconstruct', async () => {
    const { shares } = secretSharing.share(secret, 1, 1)
    const key = secretSharing.construct(shares)
    expect(key).to.deep.equals(secret)
  })

  it('2-out-of-2 share/reconstruct', async () => {
    const { shares } = secretSharing.share(secret, 2, 2)
    const key = secretSharing.construct(shares)
    expect(key).to.deep.equals(secret)
  })

  it('2-out-of-3 share/reconstruct', async () => {
    const { shares } = secretSharing.share(secret, 2, 3)
    const key = secretSharing.construct(shares.filter((_, i) => i !== 1))
    expect(key).to.deep.equals(secret)
  })

  it('2-out-of-4 share/reconstruct', async () => {
    const { shares } = secretSharing.share(secret, 2, 4)
    const key = secretSharing.construct(
      shares.filter((_, i) => i !== 0 && i !== 1),
    )
    expect(key).to.deep.equals(secret)
  })

  it('3-out-of-4 share/reconstruct', async () => {
    const { shares } = secretSharing.share(secret, 3, 4)
    const key = secretSharing.construct(shares.filter((_, i) => i !== 3))
    expect(key).to.deep.equals(secret)
  })

  it('1000-out-of-1000 share/reconstruct', async () => {
    const { shares } = secretSharing.share(secret, 1000, 1000)
    const key = secretSharing.construct(shares)
    expect(key).to.deep.equals(secret)
  })

  it('additive homomorphism (2-out-of-3)', async () => {
    const a = secretSharing.ff.encode(secretSharing.ff.rand())
    const b = secretSharing.ff.encode(secretSharing.ff.rand())
    const c = secretSharing.ff.decode(a.redAdd(b), 32)
    const { shares: as } = secretSharing.share(
      secretSharing.ff.decode(a, 32),
      2,
      3,
    )
    const { shares: bs } = secretSharing.share(
      secretSharing.ff.decode(b, 32),
      2,
      3,
      { indice: as.map((e) => e.subarray(0, 8)) },
    )
    const cs = as
      .filter((_, i) => i !== 2)
      .map((_, i) => {
        const secret = secretSharing.ff.add(
          as[i].subarray(32),
          bs[i].subarray(32),
        )
        return concatBytes(as[i].subarray(0, 32), secret)
      })
    const _c = secretSharing.construct(cs)
    expect(c).deep.equals(_c)
  })

  it('proactivate (3-out-of-3)', async () => {
    const { shares } = secretSharing.share(secret, 3, 3)
    const { shares: updates } = secretSharing.proactivate(
      3,
      3,
      shares.map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = shares.map((share, i) =>
      secretSharing.merge(share, updates[i]),
    )
    const key = secretSharing.construct(proactiveShares)
    expect(key).to.deep.equals(secret)
  })

  it('n-extension (3-out-of-3)', async () => {
    const { shares } = secretSharing.share(secret, 3, 3)
    const r = secretSharing.ff.rand()
    const { shares: rs } = secretSharing.share(r, 3, 4, {
      indice: [...shares.map((e) => e.subarray(0, 8)), randomBytes(8)],
    })
    const zs = shares.map((share, i) =>
      concatBytes(
        share.subarray(0, 32),
        secretSharing.ff.add(share.subarray(32), rs[i].subarray(32)),
      ),
    )
    const rk = rs[rs.length - 1]
    const zk = secretSharing.interpolate(rk.subarray(0, 8), zs)
    shares.push(
      concatBytes(
        rk.subarray(0, 32),
        secretSharing.ff.sub(zk, rk.subarray(32)),
      ),
    )
    const { shares: updates } = secretSharing.proactivate(
      3,
      4,
      shares.map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = shares.map((share, i) =>
      secretSharing.merge(share, updates[i]),
    )
    const key = secretSharing.construct(proactiveShares)
    expect(key).to.deep.equals(secret)
  })

  it('n-reduction (3-out-of-4)', async () => {
    const { shares } = secretSharing.share(secret, 3, 4)
    const { shares: updates } = secretSharing.proactivate(
      3,
      3,
      shares.slice(0, 3).map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = updates.map((update, i) =>
      secretSharing.merge(shares[i], update),
    )
    const key = secretSharing.construct(proactiveShares)
    expect(key).to.deep.equals(secret)
  })

  it('t-extension (3-out-of-4)', async () => {
    const { shares } = secretSharing.share(secret, 3, 4)
    const { shares: updates } = secretSharing.proactivate(
      4,
      4,
      shares.map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = updates.map((update, i) =>
      secretSharing.merge(shares[i], update),
    )
    const key = secretSharing.construct(proactiveShares)
    expect(key).to.deep.equals(secret)
  })

  it('t-reduction (3-out-of-3)', async () => {
    const { shares } = secretSharing.share(secret, 3, 3)
    const r = secretSharing.ff.rand()
    const { shares: rs } = secretSharing.share(r, 2, 3, {
      indice: shares.map((e) => e.subarray(0, 8)),
    })
    const zs = shares.map((share, i) =>
      concatBytes(
        share.subarray(0, 32),
        secretSharing.ff.add(share.subarray(32), rs[i].subarray(32)),
      ),
    )
    const ft1 = secretSharing.ft1(zs)
    const updatedShares = shares.map((share) => {
      const i = share.subarray(0, 8)
      const t = share.subarray(8, 16)
      const n = share.subarray(16, 24)
      const id = share.subarray(24, 32)
      const s = share.subarray(32)
      return concatBytes(
        i,
        t,
        n,
        id,
        secretSharing.ff.sub(
          s,
          secretSharing.ff.mul(ft1, secretSharing.ff.pow(i, 2)),
        ),
      )
    })
    const { shares: updates } = secretSharing.proactivate(
      2,
      3,
      updatedShares.map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = updatedShares.map((share, i) =>
      secretSharing.merge(share, updates[i]),
    )
    const key = secretSharing.construct([
      proactiveShares[0],
      proactiveShares[1],
    ])
    expect(key).to.deep.equals(secret)
  })
})

describe('Threshold Signature Scheme in BE', function () {
  const secretSharing = new SecretSharing(ECTSS.ff)
  const secret = ECTSS.ff.rand()

  it('1-out-of-1 share/reconstruct', async () => {
    const { shares } = secretSharing.share(secret, 1, 1)
    const key = secretSharing.construct(shares)
    expect(key).to.deep.equals(secret)
  })

  it('2-out-of-2 share/reconstruct', async () => {
    const { shares } = secretSharing.share(secret, 2, 2)
    const key = secretSharing.construct(shares)
    expect(key).to.deep.equals(secret)
  })

  it('2-out-of-3 share/reconstruct', async () => {
    const { shares } = secretSharing.share(secret, 2, 3)
    const key = secretSharing.construct(shares.filter((_, i) => i !== 1))
    expect(key).to.deep.equals(secret)
  })

  it('2-out-of-4 share/reconstruct', async () => {
    const { shares } = secretSharing.share(secret, 2, 4)
    const key = secretSharing.construct(
      shares.filter((_, i) => i !== 0 && i !== 1),
    )
    expect(key).to.deep.equals(secret)
  })

  it('3-out-of-4 share/reconstruct', async () => {
    const { shares } = secretSharing.share(secret, 3, 4)
    const key = secretSharing.construct(shares.filter((_, i) => i !== 3))
    expect(key).to.deep.equals(secret)
  })

  it('1000-out-of-1000 share/reconstruct', async () => {
    const { shares } = secretSharing.share(secret, 1000, 1000)
    const key = secretSharing.construct(shares)
    expect(key).to.deep.equals(secret)
  })

  it('additive homomorphism (2-out-of-3)', async () => {
    const a = secretSharing.ff.encode(secretSharing.ff.rand())
    const b = secretSharing.ff.encode(secretSharing.ff.rand())
    const c = secretSharing.ff.decode(a.redAdd(b), 32)
    const { shares: as } = secretSharing.share(
      secretSharing.ff.decode(a, 32),
      2,
      3,
    )
    const { shares: bs } = secretSharing.share(
      secretSharing.ff.decode(b, 32),
      2,
      3,
      { indice: as.map((e) => e.subarray(0, 8)) },
    )
    const cs = as
      .filter((_, i) => i !== 2)
      .map((_, i) => {
        const secret = secretSharing.ff.add(
          as[i].subarray(32),
          bs[i].subarray(32),
        )
        return concatBytes(as[i].subarray(0, 32), secret)
      })
    const _c = secretSharing.construct(cs)
    expect(c).deep.equals(_c)
  })

  it('proactivate (3-out-of-3)', async () => {
    const { shares } = secretSharing.share(secret, 3, 3)
    const { shares: updates } = secretSharing.proactivate(
      3,
      3,
      shares.map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = shares.map((share, i) =>
      secretSharing.merge(share, updates[i]),
    )
    const key = secretSharing.construct(proactiveShares)
    expect(key).to.deep.equals(secret)
  })

  it('n-extension (3-out-of-3)', async () => {
    const { shares } = secretSharing.share(secret, 3, 3)
    const r = secretSharing.ff.rand()
    const { shares: rs } = secretSharing.share(r, 3, 4, {
      indice: [...shares.map((e) => e.subarray(0, 8)), randomBytes(8)],
    })
    const zs = shares.map((share, i) =>
      concatBytes(
        share.subarray(0, 32),
        secretSharing.ff.add(share.subarray(32), rs[i].subarray(32)),
      ),
    )
    const rk = rs[rs.length - 1]
    const zk = secretSharing.interpolate(rk.subarray(0, 8), zs)
    shares.push(
      concatBytes(
        rk.subarray(0, 32),
        secretSharing.ff.sub(zk, rk.subarray(32)),
      ),
    )
    const { shares: updates } = secretSharing.proactivate(
      3,
      4,
      shares.map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = shares.map((share, i) =>
      secretSharing.merge(share, updates[i]),
    )
    const key = secretSharing.construct(proactiveShares)
    expect(key).to.deep.equals(secret)
  })

  it('n-reduction (3-out-of-4)', async () => {
    const { shares } = secretSharing.share(secret, 3, 4)
    const { shares: updates } = secretSharing.proactivate(
      3,
      3,
      shares.slice(0, 3).map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = updates.map((update, i) =>
      secretSharing.merge(shares[i], update),
    )
    const key = secretSharing.construct(proactiveShares)
    expect(key).to.deep.equals(secret)
  })

  it('t-extension (3-out-of-4)', async () => {
    const { shares } = secretSharing.share(secret, 3, 4)
    const { shares: updates } = secretSharing.proactivate(
      4,
      4,
      shares.map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = updates.map((update, i) =>
      secretSharing.merge(shares[i], update),
    )
    const key = secretSharing.construct(proactiveShares)
    expect(key).to.deep.equals(secret)
  })

  it('t-reduction (3-out-of-3)', async () => {
    const { shares } = secretSharing.share(secret, 3, 3)
    const r = secretSharing.ff.rand()
    const { shares: rs } = secretSharing.share(r, 2, 3, {
      indice: shares.map((e) => e.subarray(0, 8)),
    })
    const zs = shares.map((share, i) =>
      concatBytes(
        share.subarray(0, 32),
        secretSharing.ff.add(share.subarray(32), rs[i].subarray(32)),
      ),
    )
    const ft1 = secretSharing.ft1(zs)
    const updatedShares = shares.map((share) => {
      const i = share.subarray(0, 8)
      const t = share.subarray(8, 16)
      const n = share.subarray(16, 24)
      const id = share.subarray(24, 32)
      const s = share.subarray(32)
      return concatBytes(
        i,
        t,
        n,
        id,
        secretSharing.ff.sub(
          s,
          secretSharing.ff.mul(ft1, secretSharing.ff.pow(i, 2)),
        ),
      )
    })
    const { shares: updates } = secretSharing.proactivate(
      2,
      3,
      updatedShares.map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = updatedShares.map((share, i) =>
      secretSharing.merge(share, updates[i]),
    )
    const key = secretSharing.construct([
      proactiveShares[0],
      proactiveShares[1],
    ])
    expect(key).to.deep.equals(secret)
  })
})
