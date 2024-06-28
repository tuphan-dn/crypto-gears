import { expect } from 'chai'
import { FiniteField, SecretSharing } from '../dist'
import { concatBytes, randomBytes } from '@noble/hashes/utils'
import { ed25519 } from '@noble/curves/ed25519'
import { secp256k1 } from '@noble/curves/secp256k1'

describe('Threshold Signature Scheme in LE', function () {
  const ff = new FiniteField(ed25519.CURVE.n, 'le')
  const ss = new SecretSharing(ff)
  const secret = ss.ff.rand().serialize()

  it('1-out-of-1 share/reconstruct', async () => {
    const shares = ss.share(secret, 1, 1)
    const key = ss.construct(shares)
    expect(key).to.deep.equals(secret)
  })

  it('2-out-of-2 share/reconstruct', async () => {
    const shares = ss.share(secret, 2, 2)
    const key = ss.construct(shares)
    expect(key).to.deep.equals(secret)
  })

  it('2-out-of-3 share/reconstruct', async () => {
    const shares = ss.share(secret, 2, 3)
    const key = ss.construct(shares.filter((_, i) => i !== 1))
    expect(key).to.deep.equals(secret)
  })

  it('2-out-of-4 share/reconstruct', async () => {
    const shares = ss.share(secret, 2, 4)
    const key = ss.construct(shares.filter((_, i) => i !== 0 && i !== 1))
    expect(key).to.deep.equals(secret)
  })

  it('3-out-of-4 share/reconstruct', async () => {
    const shares = ss.share(secret, 3, 4)
    const key = ss.construct(shares.filter((_, i) => i !== 3))
    expect(key).to.deep.equals(secret)
  })

  it('1000-out-of-1000 share/reconstruct', async () => {
    const shares = ss.share(secret, 1000, 1000)
    const key = ss.construct(shares)
    expect(key).to.deep.equals(secret)
  })

  it('additive homomorphism (2-out-of-3)', async () => {
    const a = ss.ff.rand()
    const b = ss.ff.rand()
    const c = a.add(b).serialize()
    const as = ss.share(a.serialize(), 2, 3)
    const bs = ss.share(b.serialize(), 2, 3, {
      indice: as.map((e) => e.subarray(0, 8)),
    })
    const cs = as
      .filter((_, i) => i !== 2)
      .map((_, i) => {
        const secret = ss.ff
          .norm(as[i].subarray(32))
          .add(ss.ff.norm(bs[i].subarray(32)))
        return concatBytes(as[i].subarray(0, 32), secret.serialize())
      })
    const _c = ss.construct(cs)
    expect(c).deep.equals(_c)
  })

  it('proactivate (3-out-of-3)', async () => {
    const shares = ss.share(secret, 3, 3)
    const updates = ss.proactivate(
      3,
      3,
      shares.map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = shares.map((share, i) =>
      ss.merge(share, updates[i]),
    )
    const key = ss.construct(proactiveShares)
    expect(key).to.deep.equals(secret)
  })

  it('n-extension (3-out-of-3)', async () => {
    const shares = ss.share(secret, 3, 3)
    const r = ss.ff.rand().serialize()
    const rs = ss.share(r, 3, 4, {
      indice: [...shares.map((e) => e.subarray(0, 8)), randomBytes(8)],
    })
    const zs = shares.map((share, i) =>
      concatBytes(
        share.subarray(0, 32),
        ss.ff
          .norm(share.subarray(32))
          .add(ss.ff.norm(rs[i].subarray(32)))
          .serialize(),
      ),
    )
    const rk = rs[rs.length - 1]
    const zk = ss.interpolate(rk.subarray(0, 8), zs)
    shares.push(
      concatBytes(
        rk.subarray(0, 32),
        zk.sub(ss.ff.norm(rk.subarray(32))).serialize(),
      ),
    )
    const updates = ss.proactivate(
      3,
      4,
      shares.map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = shares.map((share, i) =>
      ss.merge(share, updates[i]),
    )
    const key = ss.construct(proactiveShares)
    expect(key).to.deep.equals(secret)
  })

  it('n-reduction (3-out-of-4)', async () => {
    const shares = ss.share(secret, 3, 4)
    const updates = ss.proactivate(
      3,
      3,
      shares.slice(0, 3).map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = updates.map((update, i) =>
      ss.merge(shares[i], update),
    )
    const key = ss.construct(proactiveShares)
    expect(key).to.deep.equals(secret)
  })

  it('t-extension (3-out-of-4)', async () => {
    const shares = ss.share(secret, 3, 4)
    const updates = ss.proactivate(
      4,
      4,
      shares.map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = updates.map((update, i) =>
      ss.merge(shares[i], update),
    )
    const key = ss.construct(proactiveShares)
    expect(key).to.deep.equals(secret)
  })

  it('t-reduction (3-out-of-3)', async () => {
    const shares = ss.share(secret, 3, 3)
    const r = ss.ff.rand()
    const rs = ss.share(r.serialize(), 2, 3, {
      indice: shares.map((e) => e.subarray(0, 8)),
    })
    const zs = shares.map((share, i) =>
      concatBytes(
        share.subarray(0, 32),
        ss.ff
          .norm(share.subarray(32))
          .add(ss.ff.norm(rs[i].subarray(32)))
          .serialize(),
      ),
    )
    const ft1 = ss.ft1(zs)
    const updatedShares = shares.map((share) => {
      const index = share.subarray(0, 8)
      const t = share.subarray(8, 16)
      const n = share.subarray(16, 24)
      const id = share.subarray(24, 32)
      const s = share.subarray(32)
      return SecretSharing.compress({
        index,
        t,
        n,
        id,
        secret: ss.ff
          .norm(s)
          .sub(ss.ff.norm(ft1).mul(ss.ff.norm(index).pow(2)))
          .serialize(),
      })
    })
    const updates = ss.proactivate(
      2,
      3,
      updatedShares.map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = updatedShares.map((share, i) =>
      ss.merge(share, updates[i]),
    )
    const key = ss.construct([proactiveShares[0], proactiveShares[1]])
    expect(key).to.deep.equals(secret)
  })
})

describe('Threshold Signature Scheme in BE', function () {
  const ff = new FiniteField(secp256k1.CURVE.n, 'be')
  const ss = new SecretSharing(ff)
  const secret = ss.ff.rand().serialize()

  it('1-out-of-1 share/reconstruct', async () => {
    const shares = ss.share(secret, 1, 1)
    const key = ss.construct(shares)
    expect(key).to.deep.equals(secret)
  })

  it('2-out-of-2 share/reconstruct', async () => {
    const shares = ss.share(secret, 2, 2)
    const key = ss.construct(shares)
    expect(key).to.deep.equals(secret)
  })

  it('2-out-of-3 share/reconstruct', async () => {
    const shares = ss.share(secret, 2, 3)
    const key = ss.construct(shares.filter((_, i) => i !== 1))
    expect(key).to.deep.equals(secret)
  })

  it('2-out-of-4 share/reconstruct', async () => {
    const shares = ss.share(secret, 2, 4)
    const key = ss.construct(shares.filter((_, i) => i !== 0 && i !== 1))
    expect(key).to.deep.equals(secret)
  })

  it('3-out-of-4 share/reconstruct', async () => {
    const shares = ss.share(secret, 3, 4)
    const key = ss.construct(shares.filter((_, i) => i !== 3))
    expect(key).to.deep.equals(secret)
  })

  it('1000-out-of-1000 share/reconstruct', async () => {
    const shares = ss.share(secret, 1000, 1000)
    const key = ss.construct(shares)
    expect(key).to.deep.equals(secret)
  })

  it('additive homomorphism (2-out-of-3)', async () => {
    const a = ss.ff.rand()
    const b = ss.ff.rand()
    const c = a.add(b).serialize()
    const as = ss.share(a.serialize(), 2, 3)
    const bs = ss.share(b.serialize(), 2, 3, {
      indice: as.map((e) => e.subarray(0, 8)),
    })
    const cs = as
      .filter((_, i) => i !== 2)
      .map((_, i) => {
        const secret = ss.ff
          .norm(as[i].subarray(32))
          .add(ss.ff.norm(bs[i].subarray(32)))
        return concatBytes(as[i].subarray(0, 32), secret.serialize())
      })
    const _c = ss.construct(cs)
    expect(c).deep.equals(_c)
  })

  it('proactivate (3-out-of-3)', async () => {
    const shares = ss.share(secret, 3, 3)
    const updates = ss.proactivate(
      3,
      3,
      shares.map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = shares.map((share, i) =>
      ss.merge(share, updates[i]),
    )
    const key = ss.construct(proactiveShares)
    expect(key).to.deep.equals(secret)
  })

  it('n-extension (3-out-of-3)', async () => {
    const shares = ss.share(secret, 3, 3)
    const r = ss.ff.rand().serialize()
    const rs = ss.share(r, 3, 4, {
      indice: [...shares.map((e) => e.subarray(0, 8)), randomBytes(8)],
    })
    const zs = shares.map((share, i) =>
      concatBytes(
        share.subarray(0, 32),
        ss.ff
          .norm(share.subarray(32))
          .add(ss.ff.norm(rs[i].subarray(32)))
          .serialize(),
      ),
    )
    const rk = rs[rs.length - 1]
    const zk = ss.interpolate(rk.subarray(0, 8), zs)
    shares.push(
      concatBytes(
        rk.subarray(0, 32),
        zk.sub(ss.ff.norm(rk.subarray(32))).serialize(),
      ),
    )
    const updates = ss.proactivate(
      3,
      4,
      shares.map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = shares.map((share, i) =>
      ss.merge(share, updates[i]),
    )
    const key = ss.construct(proactiveShares)
    expect(key).to.deep.equals(secret)
  })

  it('n-reduction (3-out-of-4)', async () => {
    const shares = ss.share(secret, 3, 4)
    const updates = ss.proactivate(
      3,
      3,
      shares.slice(0, 3).map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = updates.map((update, i) =>
      ss.merge(shares[i], update),
    )
    const key = ss.construct(proactiveShares)
    expect(key).to.deep.equals(secret)
  })

  it('t-extension (3-out-of-4)', async () => {
    const shares = ss.share(secret, 3, 4)
    const updates = ss.proactivate(
      4,
      4,
      shares.map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = updates.map((update, i) =>
      ss.merge(shares[i], update),
    )
    const key = ss.construct(proactiveShares)
    expect(key).to.deep.equals(secret)
  })

  it('t-reduction (3-out-of-3)', async () => {
    const shares = ss.share(secret, 3, 3)
    const r = ss.ff.rand()
    const rs = ss.share(r.serialize(), 2, 3, {
      indice: shares.map((e) => e.subarray(0, 8)),
    })
    const zs = shares.map((share, i) =>
      concatBytes(
        share.subarray(0, 32),
        ss.ff
          .norm(share.subarray(32))
          .add(ss.ff.norm(rs[i].subarray(32)))
          .serialize(),
      ),
    )
    const ft1 = ss.ft1(zs)
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
        ss.ff
          .norm(s)
          .sub(ss.ff.norm(ft1).mul(ss.ff.norm(i).pow(2)))
          .serialize(),
      )
    })
    const updates = ss.proactivate(
      2,
      3,
      updatedShares.map((e) => e.subarray(0, 8)),
    )
    const proactiveShares = updatedShares.map((share, i) =>
      ss.merge(share, updates[i]),
    )
    const key = ss.construct([proactiveShares[0], proactiveShares[1]])
    expect(key).to.deep.equals(secret)
  })
})
