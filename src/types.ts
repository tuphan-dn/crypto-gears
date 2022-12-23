import BN from 'bn.js'

export type RedBN = ReturnType<BN['toRed']>

export enum CryptoSys {
  EdDSA,
  ECDSA,
}
