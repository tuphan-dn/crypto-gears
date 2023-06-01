import { getPublicKey, utils } from '@noble/secp256k1'
import { expect } from 'chai'
import { ECTSS, SecretSharing } from '../dist'
import { msg } from './utils'

describe('ECTSS', () => {
  const secretSharing = new SecretSharing(ECTSS.ff)
  const master = utils.randomPrivateKey()

  it('2-out-of-2 sign/verify', async () => {
    // Setup
    const publicKey = getPublicKey(master, true)
    const t = 2
    const n = 2
    // Key generation
    const sharedKeys = secretSharing.share(master, t, n)
    // Round 1
    const hashMsg = await utils.sha256(msg)
    const { shares, R, r } = ECTSS.shareRandomness(
      t,
      n,
      sharedKeys.map((e) => e.subarray(0, 8)),
    )
    // Round 2
    const sharedSigs = sharedKeys
      .slice(0, t)
      .map((sharedKey, i) =>
        ECTSS.sign(hashMsg, R, shares[i].subarray(32), sharedKey.subarray(32)),
      )
    // Validate
    const indice = sharedKeys.slice(0, t).map((e) => e.subarray(0, 8))
    const pi = secretSharing.pi(indice)
    // Correct sig
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      utils.concatBytes(
        sharedSig.subarray(0, 33),
        secretSharing.yl(sharedSig.subarray(33), pi[i]),
      ),
    )
    // Combine sigs
    const [sig] = ECTSS.addSig(correctSigs, r)
    const ok = await ECTSS.verify(hashMsg, sig, publicKey)
    expect(ok).is.true
  })

  it('2-out-of-3 sign/verify', async () => {
    // Setup
    const publicKey = getPublicKey(master, true)
    const t = 2
    const n = 3
    // Key generation
    const sharedKeys = secretSharing.share(master, t, n)
    // Round 1
    const hashMsg = await utils.sha256(msg)
    const { shares, R, r } = ECTSS.shareRandomness(
      t,
      n,
      sharedKeys.map((e) => e.subarray(0, 8)),
    )
    // Round 2
    const sharedSigs = sharedKeys
      .slice(0, t)
      .map((sharedKey, i) =>
        ECTSS.sign(hashMsg, R, shares[i].subarray(32), sharedKey.subarray(32)),
      )
    // Validate
    const indice = sharedKeys.slice(0, t).map((e) => e.subarray(0, 8))
    const pi = secretSharing.pi(indice)
    // Correct sig
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      utils.concatBytes(
        sharedSig.subarray(0, 33),
        secretSharing.yl(sharedSig.subarray(33), pi[i]),
      ),
    )
    // Combine sigs
    const [sig] = ECTSS.addSig(correctSigs, r)
    const ok = await ECTSS.verify(hashMsg, sig, publicKey)
    expect(ok).is.true
  })
})
