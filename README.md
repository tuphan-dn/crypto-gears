# Decentralized Signature (Desig)

_Multisig requires smart contracts to counts the number of signatures while Desig splits a private key into multiple pieces and each party will use its piece to sign the transaction._

# Why Multisig is bad on Solana?

**Painful for Stateless Infrastructures.** The smart contract basically will be granted permission like assets vault/transfer, configs authority, .etc. Thus, in order to execute a transaction with smart contract, the transaction including data, accounts must be stored on-chain. The process is super heavy and unable to scale. Further, if the transaction requires 2 signatures, it seems impossible.

**Lack of Composability.** Most of protocols on Solana are designated to work well with casual wallets. The casual wallet means a wallet with private key. However, smart-contract-based wallets don't have private key and must sign/verify by seeds via a "process of simulation". To make smart-contract-based wallets in multisigs adapt new protocols, the process is really time-taken.

# Why Desig is good on Solana?

Desig is just a casual wallet with private key. However, the key isn't hold by any specific party. Instead, the key will be cryptographically splitted into multiple pieces and distributed to the holders. It brings some significant values:

**Composability & Scalability.** Fully composable/compatible to Solana and all protocols on Solana.

**Security.** Cryptographically sign/verify in decentralized fashion.

**Cost.** Because all signatures were done off-chain, the fee of Desig is basically zero.

# How does Desig work?

The master privKey is cryptographically splitted in `n` child privKeys. Each child privKey will be secretly distributed to a corresponding holder.

To sign a transaction, each holder will indepently sign it and share his signature. After have all signatures, a process will combine these signatures to reconstruct a valid signature of the master privKey.

Send & Confirm the Transaction.

# Desig's Assumption

Desig is assuming the execution enviroment is Honest-but-Curious where holders act correctly following the Desig protocol. However, they will try to gain advantages learn the others' secrets.

With this assumption, Desig is secure.

# How to test?

```
yarn test
```

# References

[1] Bernstein, Daniel J., et al. ["High-speed high-security signatures."](http://ed25519.cr.yp.to/ed25519-20110926.pdf) International Workshop on Cryptographic Hardware and Embedded Systems. Springer, Berlin, Heidelberg, 2011.

[2] Bernstein, Daniel J., et al. ["TweetNaCl: A crypto library in 100 tweets."](http://tweetnacl.cr.yp.to/tweetnacl-20140917.pdf) International Conference on Cryptology and Information Security in Latin America. Springer, Cham, 2014.

[3] Gennaro, Rosario, and Steven Goldfeder. ["Fast multiparty threshold ECDSA with fast trustless setup."](https://eprint.iacr.org/2019/114.pdf) Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security. 2018.
