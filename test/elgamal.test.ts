import {
  getPublicKey as getEdPublicKey,
  utils as edUtils,
} from '@noble/ed25519'
import {
  getPublicKey as getEcPublicKey,
  utils as ecUtils,
} from '@noble/secp256k1'
import { expect } from 'chai'
import { get } from 'https'
import { ECCurve, EdCurve, ElGamal } from '../dist'
import { print } from './utils'

const getRandomPoem = async (): Promise<string> =>
  new Promise((resolve, reject) => {
    get('https://poetrydb.org/random', (re) => {
      let data = ''
      re.on('data', (chunk) => (data += chunk))
      re.on('end', () => {
        const [{ lines }] = JSON.parse(data)
        return resolve(lines.join('\n'))
      })
    }).on('error', (er) => reject(er))
  })

describe('ElGamal Encryption', function () {
  it('encrypt/decrypt on EdDSA', async () => {
    const elgamal = new ElGamal(EdCurve)
    const msg = await getRandomPoem()
    const m = new TextEncoder().encode(msg)
    const privkey = edUtils.randomPrivateKey()
    const pubkey = await getEdPublicKey(privkey)
    const c = elgamal.encrypt(m, pubkey)
    const _m = await elgamal.decrypt(c, privkey)
    print('the poem:', new TextDecoder().decode(_m))
    expect(m).to.deep.equal(_m)
  })

  it('encrypt/decrypt on ECDSA', async () => {
    const elgamal = new ElGamal(ECCurve)
    const msg = await getRandomPoem()
    const m = new TextEncoder().encode(msg)
    const privkey = ecUtils.randomPrivateKey()
    const pubkey = getEcPublicKey(privkey)
    const c = elgamal.encrypt(m, pubkey)
    const _m = await elgamal.decrypt(c, privkey)
    print('the poem:', new TextDecoder().decode(_m))
    expect(m).to.deep.equal(_m)
  })
})
