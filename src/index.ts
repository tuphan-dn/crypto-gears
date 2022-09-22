import { encode } from 'bs58'
import { getDerivedKey, genRandomness } from './tss.utils'
import { sign, hash } from './retweetnacl'
import { addPublicKey, addSig, detached, verify } from './tss'
import { construct, share } from './sss'

const msg = Buffer.from('this is a message', 'utf8')
const alice = sign.keyPair.fromSeed(
  hash(Buffer.from('alice', 'utf8')).subarray(0, 32),
)
const bob = sign.keyPair.fromSeed(
  hash(Buffer.from('bob', 'utf8')).subarray(0, 32),
)

console.log('Alice:', encode(alice.publicKey))
console.log('Bob:', encode(bob.publicKey))

const case1 = () => {
  const {
    r: [ar],
    R,
  } = genRandomness()
  const aDerivedKey = getDerivedKey(alice.secretKey)
  const sig = detached(msg, ar, aDerivedKey, R, alice.publicKey)
  console.log('case-1:', verify(msg, sig, alice.publicKey))
}

const case2 = () => {
  const publicKey = addPublicKey(alice.publicKey, bob.publicKey)
  console.log('Master public key:', encode(publicKey))
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

const case3 = () => {
  const derivedKey = getDerivedKey(alice.secretKey)
  const shares = share(derivedKey, 2, 3)
  const key = construct(shares.filter((_, i) => i !== 0))
  console.log(Buffer.from(derivedKey).toString('hex'))
  console.log(Buffer.from(key).toString('hex'))
}

case1()
case2()
case3()

const factorial = (n: number) => {
  let x = 1
  while (n > 0) x *= n--
  return x
}
const total = (n: number, k: number) => {
  return factorial(n) / factorial(n - k) / factorial(k)
}

console.log(total(10, 5))
