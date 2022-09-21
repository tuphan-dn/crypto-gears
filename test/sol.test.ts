import { encode } from 'bs58'
import {
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
} from '@solana/web3.js'
import { getDerivedKey, genRandomness } from '../src/tss.utils'
import { addPublicKey, addSig, detached } from '../src/tss'
import { alice, bob, explorer, print } from './utils'

describe('Solana Interaction', function () {
  let publicKey: PublicKey

  before(() => {
    publicKey = new PublicKey(addPublicKey(alice.publicKey, bob.publicKey))
    print('Alice:', encode(alice.publicKey))
    print('Bob:', encode(bob.publicKey))
    print('Master public key:', publicKey.toBase58())
  })

  it('send tx', async () => {
    // Build tx
    const cluster = 'https://devnet.genesysgo.net'
    const connection = new Connection(cluster, 'confirmed')
    const tx = new Transaction()
    const ix = SystemProgram.transfer({
      fromPubkey: publicKey,
      toPubkey: new PublicKey('8W6QginLcAydYyMYjxuyKQN56NzeakDE3aRFrAmocS6D'),
      lamports: 1000,
    })
    tx.add(ix)
    tx.feePayer = publicKey
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
    const aSig = detached(msg, ar, aDerivedKey, R, publicKey.toBuffer())
    // Bob signs
    const bDerivedKey = getDerivedKey(bob.secretKey)
    const bSig = detached(msg, br, bDerivedKey, R, publicKey.toBuffer())
    // Add sig
    const sig = addSig(aSig, bSig)
    tx.addSignature(tx.feePayer, Buffer.from(sig))
    // Send tx
    const txId = await connection.sendRawTransaction(tx.serialize(), {
      skipPreflight: true,
      preflightCommitment: 'confirmed',
    })
    await connection.confirmTransaction(txId, 'confirmed')
    print(explorer(txId, 'devnet'))
  })
})
