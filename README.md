# Decentralized Signature | Desig

_Multisig requires smart contracts to counts the number of signatures while Desig splits a private key into multiple pieces and each party will use its piece to sign the transaction._

# Why is Multisig bad on Solana?

**Painful for Stateless Infrastructures.** The smart contract basically will be granted permission like assets vault/transfer, configs authority, .etc. Thus, in order to execute a transaction with smart contract, the transaction including data, accounts must be stored on-chain. The process is super heavy and unable to scale. Further, if the transaction requires 2 signatures, it seems impossible.

**Lack of Composability.** Most of protocols on Solana are designated to work well with casual wallets. The casual wallet means a wallet with private key. However, smart-contract-based wallets don't have private key and must sign/verify by seeds via a "process of simulation". To make smart-contract-based wallets in multisigs adapt new protocols, the process is really time-taken.

# Why is Desig good on Solana?

Desig is just a casual wallet with private key. However, the key isn't hold by any specific party. Instead, the key will be cryptographically splitted into multiple pieces and distributed to the holders. It brings some significant values:

**Composability & Scalability.** Fully composable/compatible to Solana and all protocols on Solana.

**Security.** Cryptographically sign/verify in decentralized fashion.

**Cost.** Because all signatures were done off-chain, the fee of Desig is basically zero.

# How does Desig work?

_TL;DR. Desig idea is leveraged by Homomorphic Encryption and Shamir's Secret Sharing._

The master privKey is cryptographically splitted in `n` child privKeys. Each child privKey will be secretly distributed to a corresponding holder.

To sign a transaction, each holder will independently sign and share his/her signature. After have all signatures, a process will combine these signatures to reconstruct a valid signature of the master privKey.

Send & Confirm the transaction.

# Crytography Foundation

These following formulas are the main cryptography foundation that Desig is based on.

## Elliptic Curve Digital Signature Algorithms

### ECDSA (Secp256k1)

$$
s = r^{-1}(H(m)+R_xPriv)
$$

### EdDSA (Ed25519)

$$
s = r+H(R,Pub,m)Priv
$$

## ElGamal Publickey Encryption

### Key Generation

$$
Pub = G  \cdot Priv
$$

### Encryption

$$
E(m)=\{ c = m + r \cdot Pub, s = r \cdot G\}
$$

### Decryption

$$
D(c,s,Priv) = \{ m = c - s \cdot Priv \}
$$

## Shamir Secret Sharing (SSS)

Let $s$ be the secret in a $t-out-of-n$ Shamir Secret Sharning Scheme.

$$
\begin{align*}
  r(x)_{r_i \leftarrow \$} &= s + r_1x + ... + r_{t-1}x^{t-1} \\
  SHR(s) &= \{s_i\}_{1..n} \\
  REC(s_{i \in \{i..n\}_t}) &= s
\end{align*}
$$

Effective reconstruction:

$$
f(0) = \sum_{i=1}^{t} y_i \prod_{j=1,j \neq i}^{t} \frac{x_j-x_i}{x_j}
$$

### Homomorphism in SSS

Let's $a$ and $b$ be 2 secrets that are shared by these functions:

$$
\begin{align*}
  g(x) &= a + g_1x + ... + g_{t-1}x^{t-1} \\
  h(x) &= b + h_1x + ... + h_{t-1}x^{t-1}
\end{align*}
$$

A operation $\oplus$ is homomorphic iff $c_i = a_i \oplus b_i$ and $REC(c_{i \in \{i..n\}_t}) = a \oplus b$.

### Additive Homomorphism

Addition is homomorphic to SSS because $f(x) = g(x) + h(x) = (a+b) + (g_1+h_1)x + (g_{t-1}+h_{t-1})x^{t-1}$ and the shares $c_i = a_i + b_i$.

### Multiplicative Homomorphism

We have

$$
f(x) = g(x)h(x) = ab + ... + g_{t-1} h_{t-1} x^{2(t-1)}
$$

The the multiplication will transform a $t-out-of-n$ SSS to a $(2t-1)-out-of-n$ SSS.

| $x$    | $0$  | $1$      | $...$ | $t-1$            | $t$      |
| ------ | ---- | -------- | ----- | ---------------- | -------- |
| $g$    | $a$  | $a_1$    | $...$ | $a_{t-1}$        | $a_t$    |
| $h$    | $b$  | $b_1$    | $...$ | $b_{t-1}$        | $b_t$    |
| $f=gh$ | $ab$ | $a_1b_1$ | $...$ | $a_{t-1}b_{t-1}$ | $a_tb_t$ |

Apply Ben-Or's Degree Reduction:

$$
\begin{cases}
  z^{(1)}(x) = a_1b_1 + z^{(1)}_1x + ... + z^{(1)}_{t-1}x^{t-1}\\
  z^{(2)}(x) = a_2b_2 + z^{(2)}_1x + ... + z^{(2)}_{t-1}x^{t-1}\\
  ...\\
  z^{(t-1)}(x) = a_{t-1}b_{t-1} + z^{(t-1)}_1x + ... + z^{(t-1)}_{t-1}x^{t-1}\\
  z^{(t)}(x) = a_tb_t + z^{(t)}_1x + ... + z^{(t)}_{t-1}x^{t-1}
\end{cases}
$$

Then,

$$
\begin{align*}
  z(x) &= \sum_{i=1}^t \gamma_i z^{(i)}(x)\\
  &= \sum_{i=1}^t \gamma_i a_ib_i + \sum_{i=1}^t \gamma_i z^{(i)}_1x + ... + \sum_{i=1}^t \gamma_i z^{(i)}_{t-1}x^{t-1}\\
  &= ab + \sum_{i=1}^t \gamma_i z^{(i)}_1x + ... + \sum_{i=1}^t \gamma_i z^{(i)}_{t-1}x^{t-1}
\end{align*}
$$

By $z(x)$, we can share the new ones as the folowing table:

| $x$ | $0$  | $1$                                     | $...$ | $t-1$                                         | $t$                                     |
| --- | ---- | --------------------------------------- | ----- | --------------------------------------------- | --------------------------------------- |
| $z$ | $ab$ | $\omega_1 = \sum_i \gamma_i z^{(i)}(1)$ | $...$ | $\omega_{t-1} = \sum_i \gamma_i z^{(i)}(t-1)$ | $\omega_t = \sum_i \gamma_i z^{(i)}(t)$ |

### Debug

#### Interpolation

$$
\begin{align*}
  f(x) &= f_0 + f_1x + ... + f_{t-1}x^{t-1}\\
  &= \sum_{i=1}^{t} f(x_i) \prod_{j=1,j \neq i}^{t} \frac{x-x_j}{x_i-x_j}
\end{align*}
$$

$$
\begin{align*}
 \sum_i^L r_{n+i} h_{n+i} \prod_{j \neq n+i}^{L+R} \frac{-j}{n+i-j} &= \sum_i^L r_{n+i} (\sum_u^L h_u \prod_{j \neq u}^L \frac{n+i-j}{u-j}) \prod_{j \neq n+i}^{L+R} \frac{-j}{n+i-j}\\
 &= \sum_i^L \sum_u^L r_{n+i} h_u \prod_{j \neq u}^L \frac{n+i-j}{u-j} \prod_{j \neq n+i}^{L+R} \frac{-j}{n+i-j}\\
\end{align*}
$$

Furthermore,

$$
\begin{align*}
  r = \sum_i^L r_i \prod_{j \neq i}^L \frac{-j}{i-j} = \sum_i^L r_{n+i} \prod_{j \neq i}^L \frac{-n-i}{i-j}
\end{align*}
$$

Skip irrelevant details to a specific server $\#u$:

$$
\begin{align*}
  s_u &= \sum_i^L r_{n+i} h_u \prod_{j \neq u}^L \frac{n+i-j}{u-j} \prod_{j \neq n+i}^{L+R} \frac{-j}{n+i-j}\\
  &= \sum_i^L r_{n+i} h_u \prod_{j \neq u}^L \frac{n+i-j}{u-j} \prod_j^L \frac{-j}{n+i-j} \prod_{j \neq n+i}^R \frac{-j}{n+i-j}\\
  &= \sum_i^L r_{n+i} h_u \prod_{j \neq u}^L \frac{n+i-j}{u-j} (\frac{-u}{n+i-u} \prod_{j \neq u}^L \frac{-j}{n+i-j}) \prod_{j \neq n+i}^R \frac{-j}{n+i-j}\\
  &= \sum_i^L r_{n+i} h_u \frac{-u}{n+i-u} \prod_{j \neq u}^L \frac{-j}{u-j} \prod_{j \neq n+i}^R \frac{-j}{n+i-j}\\
  &= \sum_i^L r_{n+i} h_u \frac{-u}{n+i-u} \prod_{j \neq u}^L \frac{-j}{u-j} \prod_{j \neq i}^L \frac{-n-j}{i-j}\\
  &= h_u \prod_{j \neq u}^L \frac{j}{u-j} \sum_i^L \frac{u}{n+i-u} (r_{n+i} \prod_{j \neq i}^L \frac{-n-j}{i-j})\\
\end{align*}
$$

Another approach (For brief, the $\Sigma$ notation will include the Langrage terms as well):

$$
rh = r \sum_i^L h_i
$$

Let $l_i$ be the random share of server $\#i$ in $n$ servers s.t. $\sum_i^L l_i = 0$. The we have:

$$
r h_i = r h_i + l_i
$$

#### Beaver's Multiplication

To comupte the share $z_i$ of $rh$, we have 2 solutions of Beaver's multiplication.

With $r_i$ in the multiplication triple:

- A multiplication triple $(r_i, s_i, (rs)_i)$.
- Open $e_i = h_i - s_i$ to construct $e$.
- Compute $z_i = (rs)_i + er_i = (rs)_i + hr_i - sr_i$.

With $h_i$ in the multiplication triple:

- A multiplication triple $(s_i, h_i, (sh)_i)$.
- Open $d_i = r_i - s_i$ to construct $d$.
- Compute $z_i = (sh)_i + dh_i = (sh)_i + rh_i - sh_i$.

# Desig's Assumption

Desig is assuming that the execution environment is Honest-but-Curious. In this environment, key holders act correctly following the Desig protocol. However, they will try to gain advantages to learn the others' secret.

With this assumption, Desig is secure.

Plus, to precompute the derived keys of holders, they must know who will take part in the signing in advance. In other words, the procotol requires a pre-signing round to commit who will join the process.

# How to test?

```
yarn test
```

# References

[1] Bernstein, Daniel J., et al. ["High-speed high-security signatures."](http://ed25519.cr.yp.to/ed25519-20110926.pdf) International Workshop on Cryptographic Hardware and Embedded Systems. Springer, Berlin, Heidelberg, 2011.

[2] Bernstein, Daniel J., et al. ["TweetNaCl: A crypto library in 100 tweets."](http://tweetnacl.cr.yp.to/tweetnacl-20140917.pdf) International Conference on Cryptology and Information Security in Latin America. Springer, Cham, 2014.

[3] Cryptography behind the top 100 Cryptocurrencies. (n.d.). Retrieved November 30, 2022, from http://ethanfast.com/top-crypto.html

[4] ECDSA: Elliptic curve signatures. ECDSA: Elliptic Curve Signatures - Practical Cryptography for Developers. (n.d.). Retrieved November 30, 2022, from https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages

[5] Gennaro, Rosario, and Steven Goldfeder. ["Fast multiparty threshold ECDSA with fast trustless setup."](https://eprint.iacr.org/2019/114.pdf) Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security. 2018.

[6] Shamir, Adi. ["How to share a secret."](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) Communications of the ACM 22.11 (1979): 612-613.

## Copyright

Desig © 2023, All Rights Reserved.
