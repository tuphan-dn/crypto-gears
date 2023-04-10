import { utils as edUtils } from '@noble/ed25519'
import { utils as ecUtils } from '@noble/secp256k1'
import { expect } from 'chai'
import { ECCurve, EdCurve, ElGamal } from '../dist'

describe('ElGamal Encryption', function () {
  it('encrypt/decrypt on EdDSA', async () => {
    const elgamal = new ElGamal(EdCurve)
    const msg = EdCurve.ff.norm(edUtils.randomBytes(32))
    const privkey = edUtils.randomPrivateKey()
    const pubkey = EdCurve.getPublicKey(privkey)
    const c = elgamal.encrypt(msg, pubkey)
    const m = elgamal.decrypt(c, privkey)
    expect(msg).to.deep.equal(m)
  })

  it('encrypt/decrypt on ECDSA', async () => {
    const elgamal = new ElGamal(ECCurve)
    const msg = EdCurve.ff.norm(ecUtils.randomBytes(32))
    const privkey = ecUtils.randomPrivateKey()
    const pubkey = ECCurve.getPublicKey(privkey)
    const c = elgamal.encrypt(msg, pubkey)
    const m = elgamal.decrypt(c, privkey)
    expect(msg).to.deep.equal(m)
  })
})
