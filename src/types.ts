import type BN from 'bn.js'
import type { ECCurve } from './ectss'
import type { EdCurve } from './edtss'

export type Curve = typeof EdCurve | typeof ECCurve

export type CryptoScheme = 'eddsa' | 'ecdsa'

export enum CryptoSys {
  EdDSA,
  ECDSA,
}
