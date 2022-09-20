import { sign, scalarMult } from './tweetnacl'

const msg = Buffer.from('this is a message', 'utf8')

const alice = sign.keyPair()
const bob = sign.keyPair()

console.log(sign.keyPair.fromSecretKey(alice.secretKey).publicKey)
console.log(alice.publicKey)
console.log(scalarMult.base(alice.secretKey.subarray(0, 32)))
// const sig = sign.detached(msg, alice.secretKey)
// console.log(sig)
