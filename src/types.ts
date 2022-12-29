import BN from 'bn.js'

export type RedBN = ReturnType<BN['toRed']>

export type CryptoScheme = 'eddsa' | 'ecdsa'

export enum CryptoSys {
  EdDSA,
  ECDSA,
}
