import { encode } from 'bs58'
import { BN } from 'bn.js'
import { getDerivedKey, genRandomness } from './tss.utils'
import { sign, hash } from './retweetnacl'
import {
  addPublicKey,
  addSig,
  detached,
  generateSharedKey,
  verify,
} from './tss'
import { pi, yl } from './sss'

const msg = Buffer.from('this is a message', 'utf8')
const master = sign.keyPair.fromSeed(
  hash(Buffer.from('master', 'utf8')).subarray(0, 32),
)

const alice = sign.keyPair.fromSeed(
  hash(Buffer.from('alice', 'utf8')).subarray(0, 32),
)
const bob = sign.keyPair.fromSeed(
  hash(Buffer.from('bob', 'utf8')).subarray(0, 32),
)

console.log('Alice:', encode(alice.publicKey))
console.log('Bob:', encode(bob.publicKey))

const case1 = () => {
  const derivedKey = getDerivedKey(master.secretKey)
  const [aliceShare, bobShare, carolShare] = generateSharedKey(derivedKey, 2, 3)

  const whoWillJoin = [
    new BN(1).toArrayLike(Buffer, 'le', 8),
    new BN(2).toArrayLike(Buffer, 'le', 8),
    new BN(3).toArrayLike(Buffer, 'le', 8),
  ]
  const aDerivedKey = yl(aliceShare.subarray(32), pi(whoWillJoin)[0])
  const bDerivedKey = yl(bobShare.subarray(32), pi(whoWillJoin)[1])
  const cDerivedKey = yl(carolShare.subarray(32), pi(whoWillJoin)[2])

  console.log('Master public key:', encode(master.publicKey))
  const {
    r: [ar, br, cr],
    R,
  } = genRandomness(3)

  const aSig = detached(msg, ar, aDerivedKey, R, master.publicKey)
  const bSig = detached(msg, br, bDerivedKey, R, master.publicKey)
  const cSig = detached(msg, cr, cDerivedKey, R, master.publicKey)

  const sig = addSig(addSig(aSig, bSig), cSig)
  console.log('case-2:', verify(msg, sig, master.publicKey))
}

case1()
