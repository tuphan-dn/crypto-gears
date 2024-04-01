import { Chain } from '@ethereumjs/common'
import { sign, utils } from '@noble/secp256k1'
import {
  Transaction,
  toBeHex,
  InfuraProvider,
  formatEther,
  Wallet,
  toBigInt,
  getBytes,
} from 'ethers'
import { ECTSS, SecretSharing } from '../dist'
import { etherscan, print, priveth } from './utils'

const web3 = new InfuraProvider(
  Chain.Sepolia,
  '783c24a3a364474a8dbed638263dc410',
)
const wallet = new Wallet(priveth, web3)

const transfer = async (payer: string) => {
  // Fixed params
  const params = { to: wallet.address, value: toBeHex('1000000000') }
  // Dynamic params
  const nonce = await web3.getTransactionCount(payer)
  const { maxFeePerGas, maxPriorityFeePerGas } = await web3.getFeeData()
  const gasLimit = await web3.estimateGas(params)
  // Build tx
  const tx = Transaction.from({
    ...params,
    chainId: Chain.Sepolia,
    nonce,
    maxFeePerGas,
    maxPriorityFeePerGas,
    gasLimit,
  })
  return tx
}

const sendAndConfirm = async (signedTx: Transaction) => {
  const { hash: txId } = await web3.broadcastTransaction(signedTx.serialized)
  await web3.waitForTransaction(txId)
  return txId
}

describe('Ethereum Integration', function () {
  const secretSharing = new SecretSharing(ECTSS.ff)

  before(async () => {
    const wei = await web3.getBalance(wallet.address)
    const eth = formatEther(wei.toString())
    print('Master:', wallet.address)
    print('My balance:', eth, 'eth')
  })

  it('standalone transaction: standard sign', async () => {
    const tx = await transfer(wallet.address)
    const signedTx = await wallet.signTransaction(tx)
    const txId = await sendAndConfirm(Transaction.from(signedTx))
    print(etherscan(txId))
  })

  it('standalone transaction: manual sign', async () => {
    const tx = await transfer(wallet.address)
    const [sig, recv] = await sign(
      getBytes(tx.unsignedHash),
      Buffer.from(getBytes(wallet.privateKey)),
      {
        recovered: true,
        der: false,
      },
    )
    const signedTx = Transaction.from({
      ...tx.toJSON(),
      signature: {
        r: toBigInt(sig.slice(0, 32)),
        s: toBigInt(sig.slice(32, 64)),
        v: BigInt(recv + 35) + BigInt(tx.chainId) * BigInt(2),
      },
    })
    const txId = await sendAndConfirm(signedTx)
    print(etherscan(txId))
  })

  it('2-out-of-2 send tx', async () => {
    const t = 2
    const n = 2
    // Setup
    const derivedKey = Buffer.from(getBytes(wallet.privateKey))
    const { shares: sharedKeys } = secretSharing.share(derivedKey, t, n)
    // Build the tx
    const tx = await transfer(wallet.address)
    // Serialize the tx
    const { shares, R, r } = ECTSS.shareRandomness(
      t,
      n,
      sharedKeys.map((e) => e.subarray(0, 8)),
    )
    // Multi sig
    const sharedSigs = sharedKeys
      .slice(0, t)
      .map((sharedKey, i) =>
        ECTSS.sign(
          getBytes(tx.unsignedHash),
          R,
          shares[i].subarray(32),
          sharedKey.subarray(32),
        ),
      )
    // Validate
    const indice = sharedKeys.slice(0, t).map((e) => e.subarray(0, 8))
    const pi = secretSharing.pi(indice)
    // Correct sig
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      utils.concatBytes(
        sharedSig.subarray(0, 33),
        secretSharing.yl(sharedSig.subarray(33), pi[i]),
      ),
    )
    // Combine sigs
    const [sig, recv] = ECTSS.addSig(correctSigs, r)
    const signedTx = Transaction.from({
      ...tx.toJSON(),
      signature: {
        r: toBigInt(sig.slice(0, 32)),
        s: toBigInt(sig.slice(32, 64)),
        v: BigInt(recv + 35) + BigInt(tx.chainId) * BigInt(2),
      },
    })
    // Send the tx
    const txId = await sendAndConfirm(signedTx)
    print(etherscan(txId))
  })

  it('2-out-of-3 send tx', async () => {
    const t = 2
    const n = 3
    // Setup
    const derivedKey = Buffer.from(getBytes(wallet.privateKey))
    const { shares: sharedKeys } = secretSharing.share(derivedKey, t, n)
    // Build the tx
    const tx = await transfer(wallet.address)
    // Serialize the tx
    const { shares, R, r } = ECTSS.shareRandomness(
      t,
      n,
      sharedKeys.map((e) => e.subarray(0, 8)),
    )
    // Multi sig
    const sharedSigs = sharedKeys
      .slice(0, t)
      .map((sharedKey, i) =>
        ECTSS.sign(
          getBytes(tx.unsignedHash),
          R,
          shares[i].subarray(32),
          sharedKey.subarray(32),
        ),
      )
    // Validate
    const indice = sharedKeys.slice(0, t).map((e) => e.subarray(0, 8))
    const pi = secretSharing.pi(indice)
    // Correct sig
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      utils.concatBytes(
        sharedSig.subarray(0, 33),
        secretSharing.yl(sharedSig.subarray(33), pi[i]),
      ),
    )
    // Combine sigs
    const [sig, recv] = ECTSS.addSig(correctSigs, r)
    const signedTx = Transaction.from({
      ...tx.toJSON(),
      signature: {
        r: toBigInt(sig.slice(0, 32)),
        s: toBigInt(sig.slice(32, 64)),
        v: BigInt(recv + 35) + BigInt(tx.chainId) * BigInt(2),
      },
    })
    // Send the tx
    const txId = await sendAndConfirm(signedTx)
    print(etherscan(txId))
  })
})
