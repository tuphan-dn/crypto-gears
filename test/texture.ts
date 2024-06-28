import { Cluster, PublicKey } from '@solana/web3.js'
import { isAddress } from 'ethers'

export const msg = Buffer.from('this is a message', 'utf8')
export const print = (...args: any[]) => {
  console.group()
  console.log('\x1b[36m↳\x1b[0m', ...args, '')
  console.groupEnd()
}
export const priveth =
  '0x6f79f19cfc4df2ff8114f9c2029f9e813af7f1273661e87256fe02775ae78c25'
export const privsol =
  '24jJXyLBuCQwj8MWK8hJgjEP9Vr7fQzZGHKTxem1twZQk1oPZ3Bt7rB14RxQbRBLfFsbWjeEvDoaKbabAwJDPfyn'

/**
 * Delay by async/await
 * @param ms - milisenconds
 * @returns Void
 */
export const asyncWait = (ms: number): Promise<void> => {
  return new Promise((resolve) => setTimeout(resolve, ms))
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
  return isAddress(address)
}

export const etherscan = (
  addrOrTx: string,
  net: string = 'sepolia',
): string => {
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
