import BN from 'bn.js'

const {
  lowlevel: { L },
} = require('./retweetnacl')

const red = BN.red(new BN(L, 16, 'le'))

export const reduceL = (a: Uint8Array): Uint8Array => {
  return new BN(a, 16, 'le').toRed(red).toArrayLike(Buffer, 'le', 32)
}

export const addScalarsL = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  const _a = new BN(a, 16, 'le').toRed(red)
  const _b = new BN(b, 16, 'le').toRed(red)
  return _a.redAdd(_b).toArrayLike(Buffer, 'le', 32)
}
