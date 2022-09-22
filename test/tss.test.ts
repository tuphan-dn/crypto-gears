import { encode } from 'bs58'
import BN from 'bn.js'
import { expect } from 'chai'
import { getDerivedKey, genRandomness } from '../src/tss.utils'
import {
  addPublicKey,
  addSig,
  detached,
  verify,
  generateSharedKey,
} from '../src/tss'
import { pi, yl } from '../src/sss'
import { msg, master, alice, bob, print } from './utils'

describe('Threshold Signature Scheme', function () {
  before(() => {
    print('Master:', encode(master.publicKey))
    print('Alice:', encode(alice.publicKey))
    print('Bob:', encode(bob.publicKey))
  })

  it('1-out-of-1 sign/verify', async () => {
    const {
      r: [ar],
      R,
    } = genRandomness()
    const aDerivedKey = getDerivedKey(alice.secretKey)
    const sig = detached(msg, ar, aDerivedKey, R, alice.publicKey)
    const ok = verify(msg, sig, alice.publicKey)
    expect(ok).equal(true)
  })

  it('n-out-of-n sign/verify', async () => {
    const publicKey = addPublicKey(alice.publicKey, bob.publicKey)
    const {
      r: [ar, br],
      R,
    } = genRandomness(2)

    const aDerivedKey = getDerivedKey(alice.secretKey)
    const aSig = detached(msg, ar, aDerivedKey, R, publicKey)
    const bDerivedKey = getDerivedKey(bob.secretKey)
    const bSig = detached(msg, br, bDerivedKey, R, publicKey)

    const sig = addSig(aSig, bSig)
    const ok = verify(msg, sig, publicKey)
    expect(ok).equal(true)
  })

  it('t-out-of-n sign/verify', async () => {
    const derivedKey = getDerivedKey(master.secretKey)
    const [aliceShare, bobShare, carolShare] = generateSharedKey(
      derivedKey,
      2,
      3,
    )

    const whoWillJoin = [
      new BN(1).toArrayLike(Buffer, 'le', 8),
      new BN(2).toArrayLike(Buffer, 'le', 8),
    ]
    const aDerivedKey = yl(aliceShare.subarray(32), pi(whoWillJoin)[0])
    const bDerivedKey = yl(bobShare.subarray(32), pi(whoWillJoin)[1])

    const {
      r: [ar, br],
      R,
    } = genRandomness(2)

    const aSig = detached(msg, ar, aDerivedKey, R, master.publicKey)
    const bSig = detached(msg, br, bDerivedKey, R, master.publicKey)

    const sig = addSig(aSig, bSig)
    const ok = verify(msg, sig, master.publicKey)
    expect(ok).equal(true)
  })
})
