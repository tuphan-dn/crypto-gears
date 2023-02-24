/**
 * Credit to @raineorshine
 * https://gist.github.com/raineorshine/c8b30db96d7532e15f85fcfe72ac719c
 */

import { Chain, Common, Hardfork } from '@ethereumjs/common'
import { Transaction } from '@ethereumjs/tx'
import { sign } from '@noble/secp256k1'
import BN from 'bn.js'
import Web3 from 'web3'
import { ECTSS, ECUtil, SecretSharing } from '../dist'
import { etherscan, print, priveth } from './utils'

const cluster = 'https://goerli.infura.io/v3/783c24a3a364474a8dbed638263dc410'
const web3 = new Web3(cluster)

const transfer = async (payer: string) => {
  // Fixed params
  const params = {
    to: '0x76d8B624eFDDd1e9fC4297F82a2689315ac62d82',
    value: web3.utils.toHex('1000000000'),
  }
  // Dynamic params
  const nonce = await web3.eth.getTransactionCount(payer)
  const gasPrice = await web3.eth.getGasPrice()
  const gasLimit = await web3.eth.estimateGas(params)
  const common = new Common({
    chain: Chain.Goerli,
    hardfork: Hardfork.Istanbul,
  })
  // Build tx
  const tx = new Transaction(
    {
      ...params,
      nonce: web3.utils.toHex(nonce),
      gasLimit: web3.utils.toHex(gasLimit),
      gasPrice: web3.utils.toHex(gasPrice),
    },
    { common },
  )
  // Return tx
  return tx
}

const sendAndConfirm = async (signedTx: Transaction) => {
  const serializedTx = signedTx.serialize()
  const { transactionHash: txId } = await web3.eth.sendSignedTransaction(
    web3.utils.bytesToHex([...serializedTx]),
  )
  return txId
}

describe('Ethereum Integration', function () {
  const secretSharing = new SecretSharing(ECTSS.ff.r, 'be')
  const master = web3.eth.accounts.privateKeyToAccount(priveth)

  before(async () => {
    const wei = await web3.eth.getBalance(master.address)
    const eth = web3.utils.fromWei(wei)
    print('Master:', master.address)
    print('My balance:', eth, 'eth')
  })

  it('standalone transaction: standard sign', async () => {
    const tx = await transfer(master.address)
    const signedTx = tx.sign(
      Buffer.from(web3.utils.hexToBytes(master.privateKey)),
    )
    const txId = await sendAndConfirm(signedTx)
    print(etherscan(txId))
  })

  it('standalone transaction: manual sign', async () => {
    const tx = await transfer(master.address)
    const msg = tx.getMessageToSign(true)
    const [sig, recv] = await sign(
      msg,
      Buffer.from(web3.utils.hexToBytes(master.privateKey)),
      {
        recovered: true,
        der: false,
      },
    )
    const chainId = tx.common.chainId()
    const r = sig.slice(0, 32)
    const s = Buffer.from(sig.slice(32, 64))
    const v = BigInt(recv + 35) + chainId * BigInt(2)
    const signedTx = Transaction.fromTxData({
      ...tx.toJSON(),
      r: BigInt(web3.utils.bytesToHex([...r])),
      s: BigInt(web3.utils.bytesToHex([...s])),
      v,
    })
    const txId = await sendAndConfirm(signedTx)
    print(etherscan(txId))
  })

  it('2-out-of-2 send tx', async () => {
    const t = 2
    const n = 2
    // Setup
    const derivedKey = Buffer.from(web3.utils.hexToBytes(master.privateKey))
    const P2 = ECUtil.ff.pow(derivedKey, 2)
    const sharedKeys = secretSharing.share(derivedKey, t, n)
    // Build the tx
    const tx = await transfer(master.address)
    // Serialize the tx
    const msg = tx.getMessageToSign()
    const { shares, R, z } = ECUtil.shareRandomness(t, n)
    const Hz2 = ECUtil.ff.pow(ECUtil.ff.add(msg, ECUtil.ff.neg(z)), 2) // (H-z)^2
    // Multi sig
    const sharedSigs = sharedKeys
      .slice(0, t)
      .map((sharedKey, i) =>
        ECTSS.sign(R, shares[i].subarray(32), sharedKey.subarray(32)),
      )
    // Validate
    const indice = [1, 2].map((i) => new BN(i).toArrayLike(Buffer, 'be', 8))
    const pi = secretSharing.pi(indice)
    // Correct sig
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      secretSharing.yl(sharedSig, pi[i]),
    )
    // Combine sigs
    const [sig, recv] = ECTSS.addSig(correctSigs, msg, R, P2, Hz2)
    const chainId = tx.common.chainId()
    const r = sig.slice(0, 32)
    const s = Buffer.from(sig.slice(32, 64))
    const v = BigInt(recv + 35) + chainId * BigInt(2)
    const signedTx = Transaction.fromTxData({
      ...tx.toJSON(),
      r: BigInt(web3.utils.bytesToHex([...r])),
      s: BigInt(web3.utils.bytesToHex([...s])),
      v,
    })
    const txId = await sendAndConfirm(signedTx)
    print(etherscan(txId))
  })

  it('2-out-of-3 send tx', async () => {
    const t = 2
    const n = 3
    // Setup
    const derivedKey = Buffer.from(web3.utils.hexToBytes(master.privateKey))
    const P2 = ECUtil.ff.pow(derivedKey, 2)
    const sharedKeys = secretSharing.share(derivedKey, t, n)
    // Build the tx
    const tx = await transfer(master.address)
    // Serialize the tx
    const msg = tx.getMessageToSign()
    const { shares, R, z } = ECUtil.shareRandomness(t, n)
    const Hz2 = ECUtil.ff.pow(ECUtil.ff.add(msg, ECUtil.ff.neg(z)), 2) // (H-z)^2
    // Multi sig
    const sharedSigs = sharedKeys
      .slice(0, t)
      .map((sharedKey, i) =>
        ECTSS.sign(R, shares[i].subarray(32), sharedKey.subarray(32)),
      )
    // Validate
    const indice = [1, 2].map((i) => new BN(i).toArrayLike(Buffer, 'be', 8))
    const pi = secretSharing.pi(indice)
    // Correct sig
    const correctSigs = sharedSigs.map((sharedSig, i) =>
      secretSharing.yl(sharedSig, pi[i]),
    )
    // Combine sigs
    const [sig, recv] = ECTSS.addSig(correctSigs, msg, R, P2, Hz2)
    const chainId = tx.common.chainId()
    const r = sig.slice(0, 32)
    const s = Buffer.from(sig.slice(32, 64))
    const v = BigInt(recv + 35) + chainId * BigInt(2)
    const signedTx = Transaction.fromTxData({
      ...tx.toJSON(),
      r: BigInt(web3.utils.bytesToHex([...r])),
      s: BigInt(web3.utils.bytesToHex([...s])),
      v,
    })
    const txId = await sendAndConfirm(signedTx)
    print(etherscan(txId))
  })
})
