import { getPublicKey, utils } from '@noble/ed25519'
import { expect } from 'chai'
import { get } from 'https'
import { ElGamal } from '../dist'
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
    const msg = await getRandomPoem()
    const m = new TextEncoder().encode(msg)
    const privkey = utils.randomPrivateKey()
    const pubkey = await getPublicKey(privkey)
    const elgamal = new ElGamal()
    const c = elgamal.encrypt(m, pubkey)
    const _m = await elgamal.decrypt(c, privkey)
    print('the poem:', new TextDecoder().decode(_m))
    expect(m).to.deep.equal(_m)
  })
})
