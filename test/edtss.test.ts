import { utils } from '@noble/ed25519'
import { Keypair } from '@solana/web3.js'
import BN from 'bn.js'
import { expect } from 'chai'
import { SecretSharing, EdTSS, EdCurve } from '../dist'
import { msg } from './utils'

describe('EdTSS', function () {
  const secretSharing = new SecretSharing(EdTSS.ff)
  const master = new Keypair()

  it('2-out-of-2 sign/verify', async () => {
    // Setup
    const publicKey = master.publicKey.toBuffer()
    const derivedKey = EdCurve.getDerivedKey(master.secretKey)
    const t = 2
    const n = 2
    // Key generation
    const sharedKeys = secretSharing.share(derivedKey, t, n)

    // Round 1
    const { shares, R } = EdTSS.shareRandomness(
      t,
      n,
      sharedKeys.map((e) => e.subarray(0, 8)),
    )
    // Round 2
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
    // Validate
    const indice = sharedKeys.map((e) => e.subarray(0, 8))
    const pi = secretSharing.pi(indice)
    // Correct sig
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      utils.concatBytes(
        EdCurve.mulScalar(sharedSig.subarray(0, 32), pi[i]),
        secretSharing.yl(sharedSig.subarray(32), pi[i]),
      ),
    )
    // Combine sigs
    const sig = EdTSS.addSig(correctSigs)
    const ok = await EdTSS.verify(msg, sig, publicKey)
    expect(ok).equal(true)
  })

  it('2-out-of-3 sign/verify', async () => {
    // Setup
    const publicKey = master.publicKey.toBuffer()
    const derivedKey = EdCurve.getDerivedKey(master.secretKey)
    const t = 2
    const n = 3
    // Key generation
    const sharedKeys = secretSharing.share(derivedKey, t, n)
    // Round 1
    const { shares, R } = EdTSS.shareRandomness(
      t,
      n,
      sharedKeys.map((e) => e.subarray(0, 8)),
    )
    // Round 2
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
    // Validate
    const indice = sharedKeys
      .filter((_, i) => i !== sharedKeys.length - 1)
      .map((e) => e.subarray(0, 8))
    const pi = secretSharing.pi(indice)
    // Correct sig
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      utils.concatBytes(
        EdCurve.mulScalar(sharedSig.subarray(0, 32), pi[i]),
        secretSharing.yl(sharedSig.subarray(32), pi[i]),
      ),
    )
    // Combine sigs
    const sig = EdTSS.addSig(correctSigs)
    const ok = await EdTSS.verify(msg, sig, publicKey)
    expect(ok).is.true
  })
})
