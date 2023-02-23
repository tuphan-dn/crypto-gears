/**
 * Credit to @raineorshine
 * https://gist.github.com/raineorshine/c8b30db96d7532e15f85fcfe72ac719c
 */

import { Chain, Common, Hardfork } from '@ethereumjs/common'
import { Transaction } from '@ethereumjs/tx'
import Web3 from 'web3'
import { etherscan, print } from './utils'

const cluster = 'https://goerli.infura.io/v3/783c24a3a364474a8dbed638263dc410'
const web3 = new Web3(cluster)
const privkey =
  '0x6f79f19cfc4df2ff8114f9c2029f9e813af7f1273661e87256fe02775ae78c25'

describe('Ethereum Integration', function () {
  const account = web3.eth.accounts.privateKeyToAccount(privkey)

  it('standalone transaction', async () => {
    const wei = await web3.eth.getBalance(account.address)
    const eth = web3.utils.fromWei(wei)
    console.log('My balance:', eth)
    // Fixed params
    const params = {
      to: '0x76d8B624eFDDd1e9fC4297F82a2689315ac62d82',
      value: web3.utils.toHex('1000000000'),
    }
    // Dynamic params
    const nonce = await web3.eth.getTransactionCount(account.address)
    console.log(nonce)
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
    // Sign tx
    const signedTx = tx.sign(
      Buffer.from(web3.utils.hexToBytes(account.privateKey)),
    )
    const serializedTx = signedTx.serialize()
    const { transactionHash: txId } = await web3.eth.sendSignedTransaction(
      web3.utils.bytesToHex([...serializedTx]),
    )
    print(etherscan(txId))
  })
})
