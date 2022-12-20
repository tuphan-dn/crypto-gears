import { encode } from 'bs58'
import BN from 'bn.js'
import {
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
} from '@solana/web3.js'
import { getDerivedKey, genRandomness } from '../src/tss.utils'
import { addPublicKey, addSig, detached } from '../src/tss'
import SecretSharing from '../src/sss'
import { master, alice, bob, explorer, print } from './utils'

const cluster = 'https://devnet.genesysgo.net'
const connection = new Connection(cluster, 'confirmed')

const transfer = async (payer: PublicKey) => {
  const tx = new Transaction()
  const ix = SystemProgram.transfer({
    fromPubkey: payer,
    toPubkey: new PublicKey('8W6QginLcAydYyMYjxuyKQN56NzeakDE3aRFrAmocS6D'),
    lamports: 1000,
  })
  tx.add(ix)
  tx.feePayer = payer
  tx.recentBlockhash = (
    await connection.getLatestBlockhash('confirmed')
  ).blockhash
  return tx
}

const sendAndConfirm = async (tx: Transaction) => {
  const txId = await connection.sendRawTransaction(tx.serialize(), {
    skipPreflight: true,
    preflightCommitment: 'confirmed',
  })
  await connection.confirmTransaction(txId, 'confirmed')
  return txId
}

describe('Solana Interaction', function () {
  const secretSharing = new SecretSharing(SecretSharing.EdDSARed)

  it('n-out-of-n send tx', async () => {
    // Setup
    const publicKey = new PublicKey(
      addPublicKey(alice.publicKey, bob.publicKey),
    )
    print('Master:', publicKey.toBase58())
    print('Alice:', encode(alice.publicKey))
    print('Bob:', encode(bob.publicKey))
    // Build tx
    const tx = await transfer(publicKey)
    // Sign tx
    const msg = tx.serializeMessage()
    const {
      r: [ar, br],
      R,
    } = genRandomness(2)
    // Alice signs
    const aDerivedKey = getDerivedKey(alice.secretKey)
    const aSig = detached(msg, ar, aDerivedKey, R, publicKey.toBuffer())
    // Bob signs
    const bDerivedKey = getDerivedKey(bob.secretKey)
    const bSig = detached(msg, br, bDerivedKey, R, publicKey.toBuffer())
    // Add sig
    const sig = addSig(aSig, bSig)
    tx.addSignature(publicKey, Buffer.from(sig))
    // Send tx
    const txId = await sendAndConfirm(tx)
    print(explorer(txId, 'devnet'))
  })

  it('t-out-of-n send tx', async () => {
    // Setup
    const publicKey = new PublicKey(master.publicKey)
    print('Master:', publicKey.toBase58())
    const derivedKey = getDerivedKey(master.secretKey)
    const [aliceShare, bobShare, carolShare] = secretSharing.share(
      derivedKey,
      2,
      3,
    )
    // Preround
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
    // Build tx
    const tx = await transfer(publicKey)
    // Sign
    const {
      r: [ar, br],
      R,
    } = genRandomness(2)
    const msg = tx.serializeMessage()
    const aSig = detached(msg, ar, aDerivedKey, R, master.publicKey)
    const bSig = detached(msg, br, bDerivedKey, R, master.publicKey)
    // Add sig
    const sig = addSig(aSig, bSig)
    tx.addSignature(publicKey, Buffer.from(sig))
    // Send tx
    const txId = await sendAndConfirm(tx)
    print(explorer(txId, 'devnet'))
  })
})
