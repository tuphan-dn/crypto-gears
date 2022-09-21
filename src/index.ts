import { encode } from 'bs58'
import {
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
} from '@solana/web3.js'
import { getDerivedKey, genRandomness } from './tss.utils'
import { sign, hash } from './retweetnacl'
import { addPublicKey, addSig, detached, verify } from './tss'

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

const case3 = async () => {
  const publicKey = addPublicKey(alice.publicKey, bob.publicKey)
  console.log('Master public key:', encode(publicKey))

  // Build tx
  const cluster = 'https://devnet.genesysgo.net'
  const connection = new Connection(cluster, 'confirmed')
  const tx = new Transaction()
  const ix = SystemProgram.transfer({
    fromPubkey: new PublicKey(publicKey),
    toPubkey: new PublicKey('8W6QginLcAydYyMYjxuyKQN56NzeakDE3aRFrAmocS6D'),
    lamports: 1000,
  })
  tx.add(ix)
  tx.feePayer = new PublicKey(publicKey)
  tx.recentBlockhash = (
    await connection.getLatestBlockhash('confirmed')
  ).blockhash
  // Sign tx
  const msg = tx.serializeMessage()
  const {
    r: [ar, br],
    R,
  } = genRandomness(2)
  // Alice signs
  const aDerivedKey = getDerivedKey(alice.secretKey)
  const aSig = detached(msg, ar, aDerivedKey, R, publicKey)
  // Bob signs
  const bDerivedKey = getDerivedKey(bob.secretKey)
  const bSig = detached(msg, br, bDerivedKey, R, publicKey)
  // Add sig
  const sig = addSig(aSig, bSig)
  tx.addSignature(tx.feePayer, Buffer.from(sig))
  // Send tx
  const txId = await connection.sendRawTransaction(tx.serialize(), {
    skipPreflight: true,
    preflightCommitment: 'confirmed',
  })
  await connection.confirmTransaction(txId, 'confirmed')
  console.log('case-3:', verify(msg, sig, publicKey), txId)
}

case1()
case2()
case3()
