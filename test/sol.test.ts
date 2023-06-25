import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
} from '@solana/web3.js'
import { SecretSharing, EdTSS, EdCurve } from '../dist'
import { solscan, print, privsol } from './utils'
import { utils } from '@noble/ed25519'
import { decode } from 'bs58'

const cluster = 'https://api.devnet.solana.com'
const connection = new Connection(cluster, 'confirmed')

const transfer = async (payer: PublicKey) => {
  // Build ix
  const ix = SystemProgram.transfer({
    fromPubkey: payer,
    toPubkey: new PublicKey('8W6QginLcAydYyMYjxuyKQN56NzeakDE3aRFrAmocS6D'),
    lamports: 1000,
  })
  // Build tx
  const tx = new Transaction()
  tx.add(ix)
  tx.feePayer = payer
  tx.recentBlockhash = (
    await connection.getLatestBlockhash('confirmed')
  ).blockhash
  // Return tx
  return tx
}

const sendAndConfirm = async (signedTx: Transaction) => {
  const signature = await connection.sendRawTransaction(signedTx.serialize(), {
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
  const secretSharing = new SecretSharing(EdTSS.ff)
  const master = Keypair.fromSecretKey(decode(privsol))

  before(async () => {
    const lamports = await connection.getBalance(master.publicKey)
    const sol = lamports / LAMPORTS_PER_SOL
    print('Master:', master.publicKey.toBase58())
    print('My balance:', sol, 'sol')
  })

  it('standalone transaction: standard sign', async () => {
    const tx = await transfer(master.publicKey)
    tx.sign(master)
    const txId = await sendAndConfirm(tx)
    print(solscan(txId))
  })

  it('standalone transaction: manual sign', async () => {})

  it('2-out-of-2 send tx', async () => {
    const t = 2
    const n = 2
    // Setup
    const derivedKey = EdCurve.getDerivedKey(master.secretKey)
    const { shares: sharedKeys } = secretSharing.share(derivedKey, t, n)
    // Build the tx
    const tx = await transfer(master.publicKey)
    // Serialize the tx
    const msg = tx.serializeMessage()
    const { shares, R } = EdTSS.shareRandomness(
      t,
      n,
      sharedKeys.map((e) => e.subarray(0, 8)),
    )
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
    const indice = sharedKeys.slice(0, t).map((e) => e.subarray(0, 8))
    const pi = secretSharing.pi(indice)
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      utils.concatBytes(
        EdCurve.mulScalar(sharedSig.subarray(0, 32), pi[i]),
        secretSharing.yl(sharedSig.subarray(32), pi[i]),
      ),
    )
    // Add signatures
    const sig = EdTSS.addSig(correctSigs)
    tx.addSignature(master.publicKey, Buffer.from(sig))
    // Send the tx
    const txId = await sendAndConfirm(tx)
    print(solscan(txId))
  })

  it('2-out-of-3 send tx', async () => {
    const t = 2
    const n = 3
    // Setup
    const derivedKey = EdCurve.getDerivedKey(master.secretKey)
    const { shares: sharedKeys } = secretSharing.share(derivedKey, t, n)
    // Build the tx
    const tx = await transfer(master.publicKey)
    // Serialize the tx
    const msg = tx.serializeMessage()
    const { shares, R } = EdTSS.shareRandomness(
      t,
      n,
      sharedKeys.map((e) => e.subarray(0, 8)),
    )
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
    const indice = sharedKeys.slice(0, t).map((e) => e.subarray(0, 8))
    const pi = secretSharing.pi(indice)
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      utils.concatBytes(
        EdCurve.mulScalar(sharedSig.subarray(0, 32), pi[i]),
        secretSharing.yl(sharedSig.subarray(32), pi[i]),
      ),
    )
    // Add signatures
    const sig = EdTSS.addSig(correctSigs)
    tx.addSignature(master.publicKey, Buffer.from(sig))
    // Send the tx
    const txId = await sendAndConfirm(tx)
    print(solscan(txId))
  })
})
