import BN from 'bn.js'
import { ECTSS, EdTSS } from '../dist'

const main = async () => {
  const ed = new BN(EdTSS.ff.r.m)
  const ec = new BN(ECTSS.ff.r.m)
  console.log(ed, ec)
  console.log(ed.gt(ec))
}
main()
