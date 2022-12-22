import BN from 'bn.js'
import { expect } from 'chai'
import { SecretSharing, EdTSS, EdCurve, EdUtil } from '../dist'
import { msg, master, alice, bob, print } from './utils'

describe('Threshold Signature Scheme', function () {
  const secretSharing = new SecretSharing(EdCurve.red)

  before(() => {
    print('Master:', master.publicKey.toBase58())
    print('Alice:', alice.publicKey.toBase58())
    print('Bob:', bob.publicKey.toBase58())
  })

  it('1-out-of-1 sign/verify', async () => {
    const {
      r: [ar],
      R,
    } = EdUtil.genRandomness()
    const aDerivedKey = EdUtil.getDerivedKey(alice.secretKey)
    const sig = EdTSS.sign(msg, R, alice.publicKey.toBuffer(), ar, aDerivedKey)
    const ok = EdTSS.verify(msg, sig, alice.publicKey.toBuffer())
    expect(ok).equal(true)
  })

  it('n-out-of-n sign/verify', async () => {
    const publicKey = EdCurve.addPoint(
      alice.publicKey.toBuffer(),
      bob.publicKey.toBuffer(),
    )
    const {
      r: [ar, br],
      R,
    } = EdUtil.genRandomness(2)

    const aDerivedKey = EdUtil.getDerivedKey(alice.secretKey)
    const aSig = EdTSS.sign(msg, R, publicKey, ar, aDerivedKey)
    const bDerivedKey = EdUtil.getDerivedKey(bob.secretKey)
    const bSig = EdTSS.sign(msg, R, publicKey, br, bDerivedKey)

    const sig = EdTSS.addSig(aSig, bSig)
    const ok = EdTSS.verify(msg, sig, publicKey)
    expect(ok).equal(true)
  })

  it('t-out-of-n sign/verify', async () => {
    const derivedKey = EdUtil.getDerivedKey(master.secretKey)
    const [aliceShare, bobShare, carolShare] = secretSharing.share(
      derivedKey,
      2,
      3,
    )

    const whoWillJoin = [
      new BN(1).toArrayLike(Buffer, 'le', 8),
      new BN(2).toArrayLike(Buffer, 'le', 8),
    ]
    const aDerivedKey = secretSharing.yl(
      aliceShare.subarray(32),
      secretSharing.pi(whoWillJoin)[0],
    )
    const bDerivedKey = secretSharing.yl(
      bobShare.subarray(32),
      secretSharing.pi(whoWillJoin)[1],
    )

    const {
      r: [ar, br],
      R,
    } = EdUtil.genRandomness(2)

    const aSig = EdTSS.sign(
      msg,
      R,
      master.publicKey.toBuffer(),
      ar,
      aDerivedKey,
    )
    const bSig = EdTSS.sign(
      msg,
      R,
      master.publicKey.toBuffer(),
      br,
      bDerivedKey,
    )

    const sig = EdTSS.addSig(aSig, bSig)
    const ok = EdTSS.verify(msg, sig, master.publicKey.toBuffer())
    expect(ok).equal(true)
  })
})
