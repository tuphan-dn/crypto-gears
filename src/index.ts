import { getDerivedKey, genRandomness } from './tss.utils'
import { sign } from './retweetnacl'
import { addPublicKey, addSig, detached, verify } from './tss'

const msg = Buffer.from('this is a message', 'utf8')
const alice = sign.keyPair()
const bob = sign.keyPair()

function case1() {
  const {
    r: [ar],
    R,
  } = genRandomness()
  const aDerivedKey = getDerivedKey(alice.secretKey)
  const sig = detached(msg, ar, aDerivedKey, R, alice.publicKey)
  console.log('case-1:', verify(msg, sig, alice.publicKey))
}

function case2() {
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
  console.log('case-2:', verify(msg, sig, publicKey))
}

case1()
case2()
