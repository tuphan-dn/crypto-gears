import { getPublicKey, Signature, utils, verify } from '@noble/secp256k1'
import BN from 'bn.js'
import { expect } from 'chai'
import { ECCurve, ECTSS, ECUtil, SecretSharing } from '../dist'

const master = utils.randomPrivateKey()
const msg = Buffer.from('this is a message', 'utf8')

describe('ECDSA (Secp256k1)', () => {
  const secretSharing = new SecretSharing(ECCurve.red, 'be')

  // it('sign', async () => {
  //   // Manually sign
  //   const h = await utils.sha256(msg)
  //   const r = ECCurve.decode(ECCurve.encode(utils.randomBytes(32)), 32)
  //   const R = ECCurve.baseMul(r).subarray(1)
  //   const sig = ECTSS.sign(h, R, r, master)
  //   const ok = verify(sig, h, getPublicKey(master, true))
  //   expect(ok).is.true
  // })

  // it('2-out-of-2 sign/verify', async () => {
  //   const publicKey = getPublicKey(master, true)
  //   const t = 2
  //   const n = 2

  //   const hashMsg = await utils.sha256(msg)

  //   const sharedKeys = secretSharing.share(master, t, n)
  //   const { shares, R } = ECUtil.shareRandomness(t, n)
  //   const sharedHashMsg = secretSharing.share(hashMsg, t, n)

  //   // Multi sig
  //   const sharedSigs = sharedKeys
  //     .slice(0, t)
  //     .map((sharedKey, i) =>
  //       ECTSS.sign(
  //         sharedHashMsg[i].subarray(32),
  //         R.subarray(1),
  //         shares[i].subarray(32),
  //         sharedKey.subarray(32),
  //       ),
  //     )
  //   // Correct sig
  //   const indice = [1, 2].map((i) => new BN(i).toArrayLike(Buffer, 'be', 8))
  //   const pi = secretSharing.pi(indice)
  //   const correctSigs = sharedSigs.map((sharedSig, i) => {
  //     const { r, s } = Signature.fromDER(sharedSig)
  //     const sig = new Signature(
  //       BigInt(
  //         ECCurve.encode(
  //           secretSharing.yl(ECCurve.decode(new BN(r.toString()), 32), pi[i]),
  //         ).toString(),
  //       ),
  //       s,
  //     )
  //     return ECUtil.finalizeSig(sig)
  //   })
  //   console.log(correctSigs)

  //   const sig = ECTSS.addSig(...correctSigs)
  //   console.log(sig, sig.length)
  //   const ok = ECTSS.verify(hashMsg, sig, publicKey)
  //   expect(ok).is.true
  // })
})
