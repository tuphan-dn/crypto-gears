import { utils } from '@noble/ed25519'
import { expect } from 'chai'
import { ECCurve, EdCurve, ElGamal } from '../dist'

describe('ElGamal Encryption', function () {
  it('encrypt/decrypt on EdDSA', () => {
    const m = EdCurve.normalize(utils.randomBytes(32))
    const privkey = EdCurve.normalize(utils.randomBytes(32))
    const pubkey = EdCurve.baseMul(privkey)
    const elgamal = new ElGamal(EdCurve)
    const { c, R } = elgamal.encrypt(m, pubkey)
    const _m = elgamal.decrypt({ c, R }, privkey)
    expect(m).to.deep.equal(_m)
  })

  // it('encrypt/decrypt on ECDSA', () => {
  //   const m = ECCurve.mod(utils.randomBytes(32))
  //   const privkey = ECCurve.mod(utils.randomBytes(32))
  //   const pubkey = ECCurve.baseMul(privkey)
  //   const elgamal = new ElGamal(ECCurve)
  //   const { c, R } = elgamal.encrypt(m, pubkey)
  //   const _m = elgamal.decrypt({ c, R }, privkey)
  //   expect(m).to.deep.equal(_m)
  // })
})
