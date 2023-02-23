import { sha512 } from '@noble/hashes/sha512'
import { Cluster, Keypair, PublicKey } from '@solana/web3.js'
import Web3 from 'web3'

export const msg = Buffer.from('this is a message', 'utf8')
export const master = Keypair.fromSeed(
  sha512(Buffer.from('master', 'utf8')).subarray(0, 32),
)
export const print = (...args: any[]) => {
  console.group()
  console.log('\x1b[36m↳\x1b[0m', ...args, '')
  console.groupEnd()
}

/**
 * Validate Ethereum address
 * @param address Ethereum address
 * @returns true/false
 */
export const isEthereumAddress = (
  address: string | undefined,
): address is string => {
  if (!address) return false
  return Web3.utils.isAddress(address)
}

export const etherscan = (addrOrTx: string, net: string = 'goerli'): string => {
  const subnet = net === 'mainnet' ? '' : `${net}.`
  const pathname = isEthereumAddress(addrOrTx) ? 'address' : 'tx'
  return `https://${subnet}etherscan.io/${pathname}/${addrOrTx}`
}

/**
 * Validate Solana address
 * @param address Solana address
 * @returns true/false
 */
export const isSolanaAddress = (
  address: string | undefined,
): address is string => {
  if (!address) return false
  try {
    const publicKey = new PublicKey(address)
    if (!publicKey) throw new Error('Invalid public key')
    return true
  } catch (er) {
    return false
  }
}

export const solscan = (addrOrTx: string, net: Cluster = 'devnet'): string => {
  const pathname = isSolanaAddress(addrOrTx) ? 'account' : 'tx'
  return `https://solscan.io/${pathname}/${addrOrTx}?cluster=${net}`
}
