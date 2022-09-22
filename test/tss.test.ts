import { encode } from 'bs58'
import { getDerivedKey, genRandomness } from '../src/tss.utils'
import { addPublicKey, addSig, detached, verify } from '../src/tss'
import { msg, alice, bob, print } from './utils'

describe('Threshold Signature Scheme', function () {
  before(() => {
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
    if (!ok) throw new Error('Invalid signature')
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
    if (!ok) throw new Error('Invalid signature')
  })

  it('t-of-n sign/verify', async () => {})
})
