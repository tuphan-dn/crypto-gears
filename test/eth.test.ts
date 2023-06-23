import { Chain, Common, Hardfork } from '@ethereumjs/common'
import { Transaction } from '@ethereumjs/tx'
import { sign, utils } from '@noble/secp256k1'
import Web3 from 'web3'
import { ECTSS, SecretSharing } from '../dist'
import { asyncWait, etherscan, print, priveth } from './utils'

const cluster = 'https://goerli.infura.io/v3/783c24a3a364474a8dbed638263dc410'
const web3 = new Web3(cluster)

const transfer = async (payer: string) => {
  // Fixed params
  const params = {
    to: '0x69b84C6cE3a1b130e46a2982B92DA9A04de92aFE',
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
  while (true) {
    const { blockNumber } = await web3.eth.getTransactionReceipt(txId)
    const currentBlockNumber = await web3.eth.getBlockNumber()
    if (currentBlockNumber - blockNumber >= 2) break
    else await asyncWait(5000)
  }
  return txId
}

describe('Ethereum Integration', function () {
  const secretSharing = new SecretSharing(ECTSS.ff)
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
    const _r = sig.slice(0, 32)
    const _s = Buffer.from(sig.slice(32, 64))
    const _v = BigInt(recv + 35) + chainId * BigInt(2)
    const signedTx = Transaction.fromTxData({
      ...tx.toJSON(),
      r: BigInt(web3.utils.bytesToHex([..._r])),
      s: BigInt(web3.utils.bytesToHex([..._s])),
      v: _v,
    })
    const txId = await sendAndConfirm(signedTx)
    print(etherscan(txId))
  })

  it('2-out-of-2 send tx', async () => {
    const t = 2
    const n = 2
    // Setup
    const derivedKey = Buffer.from(web3.utils.hexToBytes(master.privateKey))
    const { shares: sharedKeys } = secretSharing.share(derivedKey, t, n)
    // Build the tx
    const tx = await transfer(master.address)
    // Serialize the tx
    const msg = tx.getMessageToSign()
    const { shares, R, r } = ECTSS.shareRandomness(
      t,
      n,
      sharedKeys.map((e) => e.subarray(0, 8)),
    )
    // Multi sig
    const sharedSigs = sharedKeys
      .slice(0, t)
      .map((sharedKey, i) =>
        ECTSS.sign(msg, R, shares[i].subarray(32), sharedKey.subarray(32)),
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
    const chainId = tx.common.chainId()
    const _r = sig.slice(0, 32)
    const _s = Buffer.from(sig.slice(32, 64))
    const _v = BigInt(recv + 35) + chainId * BigInt(2)
    const signedTx = Transaction.fromTxData({
      ...tx.toJSON(),
      r: BigInt(web3.utils.bytesToHex([..._r])),
      s: BigInt(web3.utils.bytesToHex([..._s])),
      v: _v,
    })
    // Send the tx
    const txId = await sendAndConfirm(signedTx)
    print(etherscan(txId))
  })

  it('2-out-of-3 send tx', async () => {
    const t = 2
    const n = 3
    // Setup
    const derivedKey = Buffer.from(web3.utils.hexToBytes(master.privateKey))
    const { shares: sharedKeys } = secretSharing.share(derivedKey, t, n)
    // Build the tx
    const tx = await transfer(master.address)
    // Serialize the tx
    const msg = tx.getMessageToSign()
    const { shares, R, r } = ECTSS.shareRandomness(
      t,
      n,
      sharedKeys.map((e) => e.subarray(0, 8)),
    )
    // Multi sig
    const sharedSigs = sharedKeys
      .slice(0, t)
      .map((sharedKey, i) =>
        ECTSS.sign(msg, R, shares[i].subarray(32), sharedKey.subarray(32)),
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
    const chainId = tx.common.chainId()
    const _r = sig.slice(0, 32)
    const _s = Buffer.from(sig.slice(32, 64))
    const _v = BigInt(recv + 35) + chainId * BigInt(2)
    const signedTx = Transaction.fromTxData({
      ...tx.toJSON(),
      r: BigInt(web3.utils.bytesToHex([..._r])),
      s: BigInt(web3.utils.bytesToHex([..._s])),
      v: _v,
    })
    // Send the tx
    const txId = await sendAndConfirm(signedTx)
    print(etherscan(txId))
  })
})
