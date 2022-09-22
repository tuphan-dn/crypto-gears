const {
  lowlevel: { add, gf, unpackneg, pack },
} = require('./retweetnacl')

const _invPoint = <T>(p: T): void => {
  const q = [gf(), gf(), gf(), gf()]
  const r = new Uint8Array(32)
  pack(r, p)
  unpackneg(q, r)
  for (let i = 0; i < 4; i++) p[i] = q[i]
}

export const addPoint = (a: any[], b: any[]) => {
  const p = [gf(), gf(), gf(), gf()]
  for (let i = 0; i < 4; i++) p[i] = a[i]
  add(p, b)
  return p
}

export const packPoint = (p: any[]) => {
  const x = new Uint8Array(32)
  pack(x, p)
  return x
}

export const unpackPoint = (x: Uint8Array) => {
  const p = [gf(), gf(), gf(), gf()]
  unpackneg(p, x)
  _invPoint(p)
  return p
}
