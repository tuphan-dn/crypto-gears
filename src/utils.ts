import { bytesToHex } from '@noble/hashes/utils'
import BN from 'bn.js'
import { FiniteField } from './ff'

export type RedBN = ReturnType<BN['toRed']>

export const equal = (arr: Uint8Array[]): boolean => {
  if (!arr) return true
  const [a, ...rest] = arr
  const index = rest.findIndex((b) => bytesToHex(a) !== bytesToHex(b))
  return index < 0
}

export const calcPolynomial = (
  x: Uint8Array,
  coefficients: Uint8Array[],
  ff: FiniteField,
) => {
  const _x = ff.encode(x)
  const _coefficients = coefficients.map((co) => ff.encode(co))
  let _cache = ff.ONE
  let _sum = ff.ZERO
  _coefficients.forEach((_co, i) => {
    if (i > 0) _cache = _cache.redMul(_x)
    _sum = _sum.redAdd(_cache.redMul(_co))
  })
  return ff.decode(_sum)
}
