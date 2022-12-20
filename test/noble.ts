import { getPublicKey, sign, utils } from '@noble/ed25519'
import {
  Connection,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
} from '@solana/web3.js'
import { explorer, print } from './utils'

const cluster = 'https://api.devnet.solana.com'
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

const confirm = async (signature: string) => {
  const { blockhash, lastValidBlockHeight } =
    await connection.getLatestBlockhash()
  await connection.confirmTransaction({
    signature,
    blockhash,
    lastValidBlockHeight,
  })
}

const sendAndConfirm = async (tx: Transaction) => {
  const txId = await connection.sendRawTransaction(tx.serialize(), {
    skipPreflight: true,
    preflightCommitment: 'confirmed',
  })
  await connection.confirmTransaction(txId, 'confirmed')
  return txId
}

describe('Noble x Solana', function () {
  let privateKey: Uint8Array = utils.randomPrivateKey()
  let publicKey: PublicKey
  let address: string

  it('generate wallet', async () => {
    privateKey = utils.randomPrivateKey()
    const buf = await getPublicKey(privateKey)
    publicKey = new PublicKey(buf)
    address = publicKey.toBase58()
    print(address)
  })

  it('airdrop', async () => {
    const txId = await connection.requestAirdrop(
      new PublicKey(publicKey),
      0.001 * LAMPORTS_PER_SOL,
    )
    await confirm(txId)
    const lamports = await connection.getBalance(publicKey)
    print(lamports)
  })

  it('transfer', async () => {
    const tx = await transfer(publicKey)
    const msg = tx.serializeMessage()
    const signature = await sign(msg, privateKey)
    tx.addSignature(publicKey, Buffer.from(signature))
    const txId = await sendAndConfirm(tx)
    print(explorer(txId, 'devnet'))
  })
})
