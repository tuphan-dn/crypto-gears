import { utils } from '@noble/ed25519'
import { expect } from 'chai'
import { EdCurve, ElGamal, ExtendedElGamal } from '../dist'
import { randomBytes } from '@noble/hashes/utils'

describe('ElGamal Encryption', function () {
  const elgamal = new ElGamal()
  const privkey = utils.randomPrivateKey()
  const pubkey = EdCurve.getPublicKey(privkey)

  it('encrypt/decrypt', async () => {
    for (let i = 0; i < 1000; i++) {
      const msg = randomBytes(32)
      const c = elgamal.encrypt(msg, pubkey)
      const m = elgamal.decrypt(c, privkey)
      expect(msg).to.deep.equal(m)
    }
  })
})

describe('Extended ElGamal Encryption', function () {
  const elgamal = new ExtendedElGamal()
  const privkey = utils.randomPrivateKey()
  const pubkey = EdCurve.getPublicKey(privkey)

  it('encrypt/decrypt', async () => {
    const msg = randomBytes(1024)
    const c = elgamal.encrypt(msg, pubkey)
    const m = elgamal.decrypt(c, privkey)
    expect(msg).to.deep.equal(m)
  })
})
