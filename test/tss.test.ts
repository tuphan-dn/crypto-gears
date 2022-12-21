import BN from 'bn.js'
import { expect } from 'chai'
import EdTSS, { EdCurve, EdUtil } from '../src/edtss'
import SecretSharing from '../src/sss'
import { msg, master, alice, bob, print } from './utils'

describe('Threshold Signature Scheme', function () {
  const secretSharing = new SecretSharing(SecretSharing.EdDSA)

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
    const sig = EdTSS.sign(msg, ar, aDerivedKey, R, alice.publicKey.toBuffer())
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
    const aSig = EdTSS.sign(msg, ar, aDerivedKey, R, publicKey)
    const bDerivedKey = EdUtil.getDerivedKey(bob.secretKey)
    const bSig = EdTSS.sign(msg, br, bDerivedKey, R, publicKey)

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
      ar,
      aDerivedKey,
      R,
      master.publicKey.toBuffer(),
    )
    const bSig = EdTSS.sign(
      msg,
      br,
      bDerivedKey,
      R,
      master.publicKey.toBuffer(),
    )

    const sig = EdTSS.addSig(aSig, bSig)
    const ok = EdTSS.verify(msg, sig, master.publicKey.toBuffer())
    expect(ok).equal(true)
  })
})
