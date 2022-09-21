import { addScalars, derivedKeyLength, randomnessLength } from './tss.utils'
import { addPoint, packPoint, unpackPoint } from './tss.point'
import { sign } from './retweetnacl'

const {
  lowlevel: { gf, scalarbase, modL, pack, crypto_hash },
} = require('./retweetnacl')

function _reduce(r) {
  var x = new Float64Array(64),
    i
  for (i = 0; i < 64; i++) x[i] = r[i]
  for (i = 0; i < 64; i++) r[i] = 0
  modL(r, x)
}

export const signatureLength = sign.signatureLength

/**
 * Add 2 public keys as points on the curve
 * @param aPubkey
 * @param bPubkey
 * @returns
 */
export const addPublicKey = (
  aPubkey: Uint8Array,
  bPubkey: Uint8Array,
): Uint8Array => {
  const a = unpackPoint(aPubkey.subarray(0, 32))
  const b = unpackPoint(bPubkey.subarray(0, 32))
  const pubkey = packPoint(addPoint(a, b))
  return pubkey
}

/**
 * Add shared signatures
 * @param aSig
 * @param bSig
 * @returns
 */
export const addSig = (aSig: Uint8Array, bSig: Uint8Array): Uint8Array => {
  if (aSig.length !== signatureLength || bSig.length !== signatureLength)
    throw new Error('Invalid signature length')
  // Compute R
  const aR = unpackPoint(aSig.subarray(0, 32))
  const bR = unpackPoint(bSig.subarray(0, 32))
  const R = packPoint(addPoint(aR, bR))
  // Compute s
  const s = addScalars(aSig.subarray(32, 64), bSig.subarray(32, 64))
  // Concat
  const sig = new Uint8Array(signatureLength)
  for (let i = 0; i < 32; i++) {
    sig[i] = R[i]
    sig[32 + i] = s[i]
  }
  return sig
}

/**
 * Partially signs the message by each holder
 * @param msg Message
 * @param rn Shared randomness
 * @param derivedKey Derived key
 * @param R Randomness
 * @param publicKey Master public key
 * @returns
 */
export const detached = (
  msg: Uint8Array,
  rn: Uint8Array,
  derivedKey: Uint8Array,
  R: Uint8Array,
  publicKey: Uint8Array,
) => {
  if (rn.length !== randomnessLength) throw new Error('bad randomness size')
  if (derivedKey.length !== derivedKeyLength)
    throw new Error('bad derived key size')
  if (publicKey.length !== sign.publicKeyLength)
    throw new Error('bad public key size')

  const h = new Uint8Array(64)
  const r = new Uint8Array(64)
  const x = new Float64Array(64)
  const p = [gf(), gf(), gf(), gf()]
  const n = msg.length
  const sm = new Uint8Array(64 + n)

  for (let i = 0; i < n; i++) sm[64 + i] = msg[i] // Assign M
  for (let i = 0; i < 64; i++) r[i] = rn[i] // Assign r = $
  _reduce(r)
  for (let i = 0; i < 32; i++) sm[i] = R[i] // Assign R

  // H(R,A,M)
  for (let i = 0; i < 32; i++) sm[32 + i] = publicKey[i] // Assign A
  crypto_hash(h, sm, n + 64)
  _reduce(h)

  // s = x = r + H(R,A,M)a
  for (let i = 0; i < 64; i++) x[i] = 0
  for (let i = 0; i < 32; i++) x[i] = r[i]
  for (let i = 0; i < 32; i++) {
    for (let j = 0; j < 32; j++) {
      x[i + j] += h[i] * derivedKey[j]
    }
  }

  modL(sm.subarray(32), x)

  // R = p
  scalarbase(p, r)
  pack(sm, p) // Assign R

  return sm.subarray(0, signatureLength)
}

/**
 * Verify the message. It's identical to the ed25519 verification.
 */
export const verify = sign.detached.verify
