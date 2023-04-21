import { utils as edUtils } from '@noble/ed25519'
import { utils as ecUtils } from '@noble/secp256k1'
import { expect } from 'chai'
import { ECCurve, EdCurve, ElGamal, ExtendedElGamal } from '../dist'
import { randomBytes } from '@noble/hashes/utils'

describe('ElGamal Encryption: eddsa', function () {
  const elgamal = new ElGamal(EdCurve)
  const privkey = edUtils.randomPrivateKey()
  const pubkey = EdCurve.getPublicKey(privkey)

  it('encrypt/decrypt', async () => {
    const msg = EdCurve.ff.rand()
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
    const msg = ECCurve.ff.rand()
    const c = elgamal.encrypt(msg, pubkey)
    const m = elgamal.decrypt(c, privkey)
    expect(msg).to.deep.equal(m)
  })
})

describe('Extended ElGamal Encryption', function () {
  const elgamal = new ExtendedElGamal()
  const privkey = edUtils.randomPrivateKey()
  const pubkey = EdCurve.getPublicKey(privkey)

  it('encrypt/decrypt', async () => {
    const msg = randomBytes(1024)
    const c = elgamal.encrypt(msg, pubkey)
    const m = elgamal.decrypt(c, privkey)
    expect(msg).to.deep.equal(m)
  })
})
