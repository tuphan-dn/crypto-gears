import { sha512 } from '@noble/hashes/sha512'
import { Cluster, Keypair, PublicKey } from '@solana/web3.js'

export const msg = Buffer.from('this is a message', 'utf8')
export const master = Keypair.fromSeed(
  sha512(Buffer.from('master', 'utf8')).subarray(0, 32),
)
export const alice = Keypair.fromSeed(
  sha512(Buffer.from('alice', 'utf8')).subarray(0, 32),
)
export const bob = Keypair.fromSeed(
  sha512(Buffer.from('bob', 'utf8')).subarray(0, 32),
)

export const print = (...args: any[]) => {
  console.group()
  console.log('\x1b[36m↳\x1b[0m', ...args, '')
  console.groupEnd()
}

/**
 * Validate Solana address
 * @param address Solana address
 * @returns true/false
 */
export const isAddress = (address: string | undefined): address is string => {
  if (!address) return false
  try {
    const publicKey = new PublicKey(address)
    if (!publicKey) throw new Error('Invalid public key')
    return true
  } catch (er) {
    return false
  }
}

export const explorer = (addressOrTxId: string, net: Cluster): string => {
  if (isAddress(addressOrTxId)) {
    return `https://solscan.io/account/${addressOrTxId}?cluster=${net}`
  }
  return `https://solscan.io/tx/${addressOrTxId}?cluster=${net}`
}
