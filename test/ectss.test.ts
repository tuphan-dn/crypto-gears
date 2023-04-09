import { getPublicKey, utils } from '@noble/secp256k1'
import BN from 'bn.js'
import { expect } from 'chai'
import { ECTSS, SecretSharing } from '../dist'
import { msg } from './utils'

describe('ECTSS', () => {
  const secretSharing = new SecretSharing(ECTSS.ff)
  const master = utils.randomPrivateKey()

  it('2-out-of-2 sign/verify', async () => {
    // Setup
    const publicKey = getPublicKey(master, true)
    const P2 = ECTSS.ff.pow(master, 2)
    const t = 2
    const n = 2
    // Key generation
    const sharedKeys = secretSharing.share(master, t, n)
    // Round 1
    const hashMsg = await utils.sha256(msg)
    const { shares, R, z } = ECTSS.shareRandomness(t, n)
    const Hz2 = ECTSS.ff.pow(ECTSS.ff.add(hashMsg, ECTSS.ff.neg(z)), 2) // (H-z)^2
    // Round 2
    const sharedSigs = sharedKeys
      .slice(0, t)
      .map((sharedKey, i) =>
        ECTSS.sign(R, shares[i].subarray(32), sharedKey.subarray(32)),
      )
    // Validate
    const indice = [1, 2].map((i) => new BN(i).toArrayLike(Buffer, 'be', 8))
    const pi = secretSharing.pi(indice)
    // Correct sig
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      secretSharing.yl(sharedSig, pi[i]),
    )
    // Combine sigs
    const [sig] = ECTSS.addSig(correctSigs, hashMsg, R, P2, Hz2)
    const ok = ECTSS.verify(hashMsg, sig, publicKey)
    expect(ok).is.true
  })

  it('2-out-of-3 sign/verify', async () => {
    // Setup
    const publicKey = getPublicKey(master, true)
    const P2 = ECTSS.ff.pow(master, 2)
    const t = 2
    const n = 3
    // Key generation
    const sharedKeys = secretSharing.share(master, t, n)
    // Round 1
    const hashMsg = await utils.sha256(msg)
    const { shares, R, z } = ECTSS.shareRandomness(t, n)
    const Hz2 = ECTSS.ff.pow(ECTSS.ff.add(hashMsg, ECTSS.ff.neg(z)), 2) // (H-z)^2
    // Round 2
    const sharedSigs = sharedKeys
      .slice(0, t)
      .map((sharedKey, i) =>
        ECTSS.sign(R, shares[i].subarray(32), sharedKey.subarray(32)),
      )
    // Validate
    const indice = [1, 2].map((i) => new BN(i).toArrayLike(Buffer, 'be', 8))
    const pi = secretSharing.pi(indice)
    // Correct sig
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      secretSharing.yl(sharedSig, pi[i]),
    )
    // Combine sigs
    const [sig] = ECTSS.addSig(correctSigs, hashMsg, R, P2, Hz2)
    const ok = ECTSS.verify(hashMsg, sig, publicKey)
    expect(ok).is.true
  })
})
