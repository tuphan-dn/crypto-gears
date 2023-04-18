import { utils as edUtils } from '@noble/ed25519'
import { utils as ecUtils } from '@noble/secp256k1'
import { expect } from 'chai'
import { ECCurve, EdCurve, ElGamal } from '../dist'

describe('ElGamal Encryption: eddsa', function () {
  const elgamal = new ElGamal(EdCurve)
  const privkey = edUtils.randomPrivateKey()
  const pubkey = EdCurve.getPublicKey(privkey)

  it('encrypt/decrypt', async () => {
    const msg = EdCurve.ff.norm(edUtils.randomBytes(32))
    const c = elgamal.encrypt(msg, pubkey)
    const m = elgamal.decrypt(c, privkey)
    expect(msg).to.deep.equal(m)
  })
})

describe('ElGamal Encryption: ecdsa', function () {
  const elgamal = new ElGamal(ECCurve)
  const privkey = ecUtils.randomPrivateKey()
  const pubkey = ECCurve.getPublicKey(privkey)

  it('encrypt/decrypt', async () => {
    const msg = EdCurve.ff.norm(ecUtils.randomBytes(32))
    const c = elgamal.encrypt(msg, pubkey)
    const m = elgamal.decrypt(c, privkey)
    expect(msg).to.deep.equal(m)
  })
})
