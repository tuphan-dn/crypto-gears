import { utils } from '@noble/ed25519'
import BN from 'bn.js'
import { expect } from 'chai'
import { SecretSharing, EdTSS, EdCurve, EdUtil } from '../dist'
import { msg, master, print } from './utils'

describe('Threshold Signature Scheme', function () {
  const secretSharing = new SecretSharing(EdCurve.red, 'le')

  before(() => {
    print('Master:', master.publicKey.toBase58())
  })

  it('2-out-of-2 sign/verify', async () => {
    const publicKey = master.publicKey.toBuffer()
    const derivedKey = EdUtil.getDerivedKey(master.secretKey)
    const t = 2
    const n = 2

    const sharedKeys = secretSharing.share(derivedKey, t, n)
    const { shares, R } = EdUtil.shareRandomness(t, n)

    // Multi sig
    const sharedSigs = sharedKeys
      .slice(0, t)
      .map((sharedKey, i) =>
        EdTSS.sign(
          msg,
          R,
          publicKey,
          shares[i].subarray(32),
          sharedKey.subarray(32),
        ),
      )
    // Correct sig
    const indice = [1, 2].map((i) => new BN(i).toArrayLike(Buffer, 'le', 8))
    const pi = secretSharing.pi(indice)
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      utils.concatBytes(
        EdCurve.mulScalar(sharedSig.subarray(0, 32), pi[i]),
        secretSharing.yl(sharedSig.subarray(32), pi[i]),
      ),
    )

    const sig = EdTSS.addSig(...correctSigs)
    const ok = EdTSS.verify(msg, sig, publicKey)
    expect(ok).equal(true)
  })

  it('2-out-of-3 sign/verify', async () => {
    const publicKey = master.publicKey.toBuffer()
    const derivedKey = EdUtil.getDerivedKey(master.secretKey)
    const t = 2
    const n = 3

    const sharedKeys = secretSharing.share(derivedKey, t, n)
    const { shares, R } = EdUtil.shareRandomness(t, n)

    // Multi sig
    const sharedSigs = sharedKeys
      .slice(0, t)
      .map((sharedKey, i) =>
        EdTSS.sign(
          msg,
          R,
          publicKey,
          shares[i].subarray(32),
          sharedKey.subarray(32),
        ),
      )
    // Correct sig
    const indice = [1, 2].map((i) => new BN(i).toArrayLike(Buffer, 'le', 8))
    const pi = secretSharing.pi(indice)
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      utils.concatBytes(
        EdCurve.mulScalar(sharedSig.subarray(0, 32), pi[i]),
        secretSharing.yl(sharedSig.subarray(32), pi[i]),
      ),
    )

    const sig = EdTSS.addSig(...correctSigs)
    const ok = EdTSS.verify(msg, sig, publicKey)
    expect(ok).equal(true)
  })
})
