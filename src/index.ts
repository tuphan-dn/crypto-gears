import { utils } from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha512'

utils.sha512Sync = (...m) => sha512(utils.concatBytes(...m))

export * from './ff'
export * from './sss'
export * from './ectss'
export * from './edtss'
export * from './elgamal'
export * from './types'
