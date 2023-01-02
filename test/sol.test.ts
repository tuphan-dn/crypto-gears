import BN from 'bn.js'
import {
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
} from '@solana/web3.js'
import { SecretSharing, EdTSS, EdCurve, EdUtil } from '../dist'
import { master, explorer, print } from './utils'
import { utils } from '@noble/ed25519'

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

  it('2-out-of-2 send tx', async () => {
    const t = 2
    const n = 2
    // Setup
    const derivedKey = EdUtil.getDerivedKey(master.secretKey)
    const sharedKeys = secretSharing.share(derivedKey, t, n)
    print('Master:', master.publicKey.toBase58())
    // Build the tx
    const tx = await transfer(master.publicKey)
    // Serialize the tx
    const msg = tx.serializeMessage()
    const indice = [1, 2].map((i) => new BN(i).toArrayLike(Buffer, 'le', 8))
    const pi = secretSharing.pi(indice)
    const { shares, R } = EdUtil.shareRandomness(t, n)
    // Multi sig
    const sharedSigs = sharedKeys
      .slice(0, t)
      .map((sharedKey, i) =>
        EdTSS.sign(
          msg,
          R,
          master.publicKey.toBuffer(),
          shares[i].subarray(32),
          sharedKey.subarray(32),
        ),
      )
    // Correct sig
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      utils.concatBytes(
        EdCurve.mulScalar(sharedSig.subarray(0, 32), pi[i]),
        secretSharing.yl(sharedSig.subarray(32), pi[i]),
      ),
    )
    // Add signatures
    const sig = EdTSS.addSig(correctSigs[0], correctSigs[1])
    tx.addSignature(master.publicKey, Buffer.from(sig))
    // Send the tx
    const txId = await sendAndConfirm(tx)
    print(explorer(txId, 'devnet'))
  })

  it('2-out-of-3 send tx', async () => {
    const t = 2
    const n = 3
    // Setup
    const derivedKey = EdUtil.getDerivedKey(master.secretKey)
    const sharedKeys = secretSharing.share(derivedKey, t, n)
    print('Master:', master.publicKey.toBase58())
    // Build the tx
    const tx = await transfer(master.publicKey)
    // Serialize the tx
    const msg = tx.serializeMessage()
    const indice = [1, 2].map((i) => new BN(i).toArrayLike(Buffer, 'le', 8))
    const pi = secretSharing.pi(indice)
    const { shares, R } = EdUtil.shareRandomness(t, n)
    // Multi sig
    const sharedSigs = sharedKeys
      .slice(0, t)
      .map((sharedKey, i) =>
        EdTSS.sign(
          msg,
          R,
          master.publicKey.toBuffer(),
          shares[i].subarray(32),
          sharedKey.subarray(32),
        ),
      )
    // Correct sig
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      utils.concatBytes(
        EdCurve.mulScalar(sharedSig.subarray(0, 32), pi[i]),
        secretSharing.yl(sharedSig.subarray(32), pi[i]),
      ),
    )
    // Add signatures
    const sig = EdTSS.addSig(correctSigs[0], correctSigs[1])
    tx.addSignature(master.publicKey, Buffer.from(sig))
    // Send the tx
    const txId = await sendAndConfirm(tx)
    print(explorer(txId, 'devnet'))
  })
})
