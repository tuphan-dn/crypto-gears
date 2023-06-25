import { utils, verify } from '@noble/ed25519'
import { Keypair } from '@solana/web3.js'
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
    const { shares: sharedKeys, zkp: pzkp } = secretSharing.share(
      derivedKey,
      t,
      n,
      {
        ec: EdCurve,
      },
    )
    if (!pzkp) throw new Error('Invalid zk proofs')
    // Round 1
    const {
      shares,
      R,
      zkp: rzkp,
    } = EdTSS.shareRandomness(
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
    let ok = sharedSigs
      .map((sig, i) =>
        EdTSS.verify(
          msg,
          R,
          publicKey,
          sharedKeys[i].subarray(0, 8),
          sig,
          pzkp,
          rzkp,
        ),
      )
      .reduce((ok, e) => ok && e, true)
    // Correct sig
    const indice = sharedKeys.map((e) => e.subarray(0, 8))
    const pi = secretSharing.pi(indice)
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      utils.concatBytes(
        EdCurve.mulScalar(sharedSig.subarray(0, 32), pi[i]),
        secretSharing.yl(sharedSig.subarray(32), pi[i]),
      ),
    )
    // Combine sigs
    const sig = EdTSS.addSig(correctSigs)
    ok = ok && (await verify(sig, msg, publicKey))
    expect(ok).equal(true)
  })

  it('2-out-of-3 sign/verify', async () => {
    // Setup
    const publicKey = master.publicKey.toBuffer()
    const derivedKey = EdCurve.getDerivedKey(master.secretKey)
    const t = 2
    const n = 3
    // Key generation
    const { shares: sharedKeys, zkp: pzkp } = secretSharing.share(
      derivedKey,
      t,
      n,
      { ec: EdCurve },
    )
    if (!pzkp) throw new Error('Invalid zk proofs')
    // Round 1
    const {
      shares,
      R,
      zkp: rzkp,
    } = EdTSS.shareRandomness(
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
    let ok = sharedSigs
      .map((sig, i) =>
        EdTSS.verify(
          msg,
          R,
          publicKey,
          sharedKeys[i].subarray(0, 8),
          sig,
          pzkp,
          rzkp,
        ),
      )
      .reduce((ok, e) => ok && e, true)
    // Correct sig
    const indice = sharedKeys
      .filter((_, i) => i !== sharedKeys.length - 1)
      .map((e) => e.subarray(0, 8))
    const pi = secretSharing.pi(indice)
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      utils.concatBytes(
        EdCurve.mulScalar(sharedSig.subarray(0, 32), pi[i]),
        secretSharing.yl(sharedSig.subarray(32), pi[i]),
      ),
    )
    // Combine sigs
    const sig = EdTSS.addSig(correctSigs)
    ok = ok && (await verify(sig, msg, publicKey))
    expect(ok).is.true
  })
})
