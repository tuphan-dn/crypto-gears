import BN from 'bn.js'
import {
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
} from '@solana/web3.js'
import EdTSS, { EdCurve, EdUtil } from '../src/edtss'
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
  const signature = await connection.sendRawTransaction(tx.serialize(), {
    skipPreflight: true,
    preflightCommitment: 'confirmed',
  })
  const { blockhash, lastValidBlockHeight } =
    await connection.getLatestBlockhash()
  await connection.confirmTransaction({
    signature,
    blockhash,
    lastValidBlockHeight,
  })
  return signature
}

describe('Solana Interaction', function () {
  const secretSharing = new SecretSharing(EdCurve.red)

  it('n-out-of-n send tx', async () => {
    // Setup
    const publicKey = new PublicKey(
      EdCurve.addPoint(alice.publicKey.toBuffer(), bob.publicKey.toBuffer()),
    )
    print('Master:', publicKey.toBase58())
    print('Alice:', alice.publicKey.toBase58())
    print('Bob:', bob.publicKey.toBase58())
    // Build tx
    const tx = await transfer(publicKey)
    // Sign tx
    const msg = tx.serializeMessage()
    const {
      r: [ar, br],
      R,
    } = EdUtil.genRandomness(2)
    // Alice signs
    const aDerivedKey = EdUtil.getDerivedKey(alice.secretKey)
    const aSig = EdTSS.sign(msg, R, publicKey.toBuffer(), ar, aDerivedKey)
    // Bob signs
    const bDerivedKey = EdUtil.getDerivedKey(bob.secretKey)
    const bSig = EdTSS.sign(msg, R, publicKey.toBuffer(), br, bDerivedKey)
    // Add sig
    const sig = EdTSS.addSig(aSig, bSig)
    tx.addSignature(publicKey, Buffer.from(sig))
    // Send tx
    const txId = await sendAndConfirm(tx)
    print(explorer(txId, 'devnet'))
  })

  it('t-out-of-n send tx', async () => {
    // Setup
    const publicKey = new PublicKey(master.publicKey)
    print('Master:', publicKey.toBase58())
    const derivedKey = EdUtil.getDerivedKey(master.secretKey)
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
    } = EdUtil.genRandomness(2)
    const msg = tx.serializeMessage()
    const aSig = EdTSS.sign(
      msg,
      R,
      master.publicKey.toBuffer(),
      ar,
      aDerivedKey,
    )
    const bSig = EdTSS.sign(
      msg,
      R,
      master.publicKey.toBuffer(),
      br,
      bDerivedKey,
    )
    // Add sig
    const sig = EdTSS.addSig(aSig, bSig)
    tx.addSignature(publicKey, Buffer.from(sig))
    // Send tx
    const txId = await sendAndConfirm(tx)
    print(explorer(txId, 'devnet'))
  })
})
