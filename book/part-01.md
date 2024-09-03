## DICP - Part 1


### 1.1 Cipher
A *cipher* defines a pair of functions, *encryption* and *decryption*, where one is an inverse of the other. These two operations of a cipher are defined under a *key*.

The key, plaintext, and ciphertext are defined as strings over {0, 1}.

A *key* is a secret shared between honest parties (or peers) that have agreed to use a specific cipher to  exchange data. A cipher is expected to give higher guarantees about confidentiality of data - the assurance that it is computationally infeasible for an adversary who doesn't have access to the secret key to obtain plaintext from a (possibly leaked) ciphertext.

Two popular examples of ciphers are [AES](#xref-fips-197-aes) and [ChaCha20](#xref-ietf-cc20p1305).

Cryptography protocols assume that a key is uniformly drawn from a large set. One may imagine, for instance, that all 128 bits of an AES128 key to be drawn from some source of randomness. In real-world protocols, however, AES128 key is *derived* interactively using a combination of other primitives, *schemes*, and functions called *Key Derivation Functions* (KDFs).

The encryption function, $Enc_k$, defined under a key, maps plaintext to a ciphertext. The decryption function, $Dec_k$, defined under the same key, maps ciphertext to plaintext.

<a id="xref-def-cipher-correctness"></a>
#### Defintion 1.1.1 Correctness Requirement for Ciphers
$Enc_k$ and $Dec_k$ are total functions, and for every plaintext $m \in M$, the following must hold

$$
    Dec_k(Enc_k(m)) = m
$$

In other words, encrypting a message and then decrypting the resulting ciphertext using the same key must yield the original message.

:black_square_button:


A cipher is defined by three parameters - the key length, the plaintext block length, and the ciphertext block length. AES defines 128 bit block size, while the key may assume one of the three sizes: 128 bit, 192 bit, and 256 bit.


### 1.2 Block
A block is a sequence of bytes. It is common to specify the length of a block in number of bits. AES algorithm always uses a block of size 128 bits (16 bytes). ChaCha20 processes inputs in blocks of size 512 bits (64 butes).


### 1.3 Block Cipher
A block cipher is a primitive used in the design of symmetric-key cryptography schemes. A block cipher only processes inputs one block at a time. Each block is of fixed size. The AES block cipher, for example, defines block size od 128 bits,

A block cipher defines functions to convert a block of plaintext into a ciphertext block, and vice-versa. The function which converts a plaintext block into a ciphertext block is the *forward operation*, commonly called as the *encryption* function. The *inverse operation* which conervts a block of ciphertext to a plaintext block is called the *decryption* function.

Block cipher's encryption function takes a key and a plaintext block as inputs, and produces a block of ciphertext:

$$
    {Enc: K \times M \rightarrow  S}
$$

where

```math
{\begin{array}{rll}
    Key & K &\in & \{0, 1 \}^k\\
    Plaintext & M & \in & \{ 0, 1 \}^n\\
    Ciphertext & S & \in & \{ 0, 1 \}^n\\
\end{array}}
```


[FIPS 197](#xref-fips-197-aes) is the official publication of Advanced Encryption Standard (AES). The section 2 of the publication provides definitions of the terms used in the document. Here are three terms of our immediate interest:

|         |                 |
| :------ | :-------        |
| Block   | A sequence of bits of a given fixed length. In this Standard, blocks consist of 128 bits, sometimes represented as arrays of bytes or words.|
| Block&nbsp;cipher | A family of permutations of blocks that is parameterized by the key.|
| Key | The parameter of a block cipher that determines the selection of a permutation from the block cipher family.|
|         |                 |

Note that a block cipher defines a *family of permutations*, and a key value *selects a specific permutation* from the family of permutations.

The section 4 of [NIST Special Publication 800-38A, Recommendation for Block Cipher Modes of Operation](#xref-nist-800-38A-block-cipher-modes), offers the following definitions (empahis added):

|         |                 |
| :------ | :-------        |
| Block&nbsp;cipher    | A family of functions and their inverse functions that is parameterized by cryptographic keys; the functions map bit strings of a fixed length to bit strings of the same length.|
| Cryptographic&nbsp;Key | A parameter used in the block cipher algorithm that determines the *forward cipher operation* and the *inverse cipher operation*.|
|         |                 |


### 1.3.1 A Family of Functions Mapping Plaintext to Glyphtext

Before trying to understand the meaning of a *family of permutations*, let us first grasp the meaning of the term *family of functions*. Let us start with the following definitions:

```math
    {\begin{array}{rllll}
    & K & \in & \{0, 1\}^3 & \text{3 bit keys} \\
    & M & \in & \{a, b\}^3 & \text{3 letter plaintext comprised of} \ a\text{'s and } b \text{'s} \\
    & G & \in & \{\boxdot, \circledast\}^3 & \text{3 letter glyphtext containing}  \boxdot  \text{and} \ \circledast \\
    \end{array}}
```

As the cardinality of each set is small, we will enumerate their members:

```math
    {\begin{array}{rrlll}
    Key & K & \in & \{000, 001, 010, 011, 100, 101, 110, 111 \}\\
    Plaintext & M & \in & \{aaa, aab, aba, abb, baa, bab, bba, bbb \}\\
    Glyphtext & G & \in & \{\boxdot\boxdot\boxdot, \boxdot\boxdot\circledast, \boxdot\circledast\boxdot,    \boxdot\circledast\circledast,
                \circledast\boxdot\boxdot,  \circledast \boxdot \circledast, \circledast\circledast\boxdot, \circledast\circledast\circledast\}\\
    \end{array}}
```

A family of functions share common domain and range. A distinctive feature is the presence of at least one parameter that can be set to different values to produce different member functions in the family. This allows a scheme to create new functions from a single general form.

In computer science too, a function can be partially applied to one parameter yielding another function. This is called *currying*. Currying is a method for transforming a function that takes multiple arguments into a sequence of families of functions, each taking a single argument.

Let us review the form of encoding and decoding functions, E and D, respectively.

#### Definition 1.3.1.1
```math
    {\begin{array}{rrl}
        \text{family of forward functions} & E: & K \times M \rightarrow G\\
        \text{family of inverse functions} & D: & K \times G \rightarrow M\\
    \end{array}}
```

:black_square_button:

Choosing a specific key value for K produces a pair of functions:

#### Definition 1.3.1.2
```math
    {\begin{array}{rrl}
        \text{forward function} & E_k: & M \rightarrow G\\
        \text{inverse function} & D_k: & G \rightarrow M\\
    \end{array}}
```

:black_square_button:

#### Defintion 1.3.1.3 Correctness Requirement
$E_k$ and $D_k$ are total functions, and for every plaintext $m \in M$, the following must hold

$$
    {D_k(E_k(m)) = m}
$$

In other words, encoding a plaintext and then decoding the resulting glyphtext using the same key must yieldt the original plaintext.

:black_square_button:


We will now try to define a *family of functions* where each member function maps plaintext to glyphtext. We will identify each function with a key. As there are eight keys, we will have eight functions: \{ $E_{000}$, $E_{001}$, $E_{010}$, $E_{011}$, $E_{100}$, $E_{101}$, $E_{110}$, $E_{111}$ \}. This is essentially the family of functions we have in this example. Selecting a key implies selecting a function from this family of functions.


In general, if a scheme has a parameter *n* defining the length of individual keys, there will be $2^n$ unique keys, each defining a unique function. In that case, family of functions will have $2^n$ functions.



To simplify presentation, let us define a table per function. In other words, we have a *family of tables* where each table represents a *forward function* mapping plaintext to glyphtext. (It should be obvious that we will use the same tables to define the *inverse* functions too).

In the following tables, we will place the function name in the top-left header column. The plaintext strings are named $m_0$, $m_1$,$...$,$m_5$, $m_6$, and $m_7$.



| $E_{000}$ | Plaintext |       Glyphtext                     |
|    ----:  | :--------:| :---------------------------------: |
|    $m_0$  | aaa       | $\boxdot\boxdot\boxdot$             |
|    $m_1$  | aab       | $\boxdot\boxdot\circledast$         |
|    $m_2$  | aba       | $\boxdot\circledast\boxdot$         |
|    $m_3$  | abb       | $\boxdot\circledast\circledast$     |
|    $m_4$  | baa       | $\circledast\boxdot\boxdot$         |
|    $m_5$  | bab       | $\circledast\boxdot\circledast$     |
|    $m_6$  | bba       | $\circledast\circledast\boxdot$     |
|    $m_7$  | bbb       | $\circledast\circledast\circledast$ |




| $E_{001}$ | Plaintext |       Glyphtext                     |
|    ----:  | :--------:| :---------------------------------: |
|    $m_0$  | aaa       | $\boxdot\boxdot\circledast$         |
|    $m_1$  | aab       | $\boxdot\circledast\boxdot$         |
|    $m_2$  | aba       | $\boxdot\circledast\circledast$     |
|    $m_3$  | abb       | $\circledast\boxdot\boxdot$         |
|    $m_4$  | baa       | $\circledast\boxdot\circledast$     |
|    $m_5$  | bab       | $\circledast\circledast\boxdot$     |
|    $m_6$  | bba       | $\circledast\circledast\circledast$ |
|    $m_7$  | bbb       | $\boxdot\boxdot\boxdot$             |



| $E_{002}$ | Plaintext |       Glyphtext                     |
|    ----:  | :--------:| :---------------------------------: |
|    $m_0$  | aaa       | $\boxdot\circledast\boxdot$         |
|    $m_1$  | aab       | $\boxdot\circledast\circledast$     |
|    $m_2$  | aba       | $\circledast\boxdot\boxdot$         |
|    $m_3$  | abb       | $\circledast\boxdot\circledast$     |
|    $m_4$  | baa       | $\circledast\circledast\boxdot$     |
|    $m_5$  | bab       | $\circledast\circledast\circledast$ |
|    $m_6$  | bba       | $\boxdot\boxdot\boxdot$             |
|    $m_7$  | bbb       | $\boxdot\boxdot\circledast$         |


Notice that it is equally easy to compute the *inverse function*, $D$. Given `key` and the glyphtext $G$, function $D_{key}$ looks up the given value $G$ under `Glyphtext` column, and returns `Plaintext` value in the same row (`r`).

Continuiing this way, we define $E_{006}$ and $E_{007}$, the last two functions in the family:

| $E_{006}$ | Plaintext |       Glyphtext                     |
|    ----:  | :--------:| :---------------------------------: |
|    $m_0$  | aaa       | $\circledast\circledast\boxdot$     |
|    $m_1$  | aab       | $\circledast\circledast\circledast$ |
|    $m_2$  | aba       | $\boxdot\boxdot\boxdot$             |
|    $m_3$  | abb       | $\boxdot\boxdot\circledast$         |
|    $m_4$  | baa       | $\boxdot\circledast\boxdot$         |
|    $m_5$  | bab       | $\circledast\boxdot\boxdot$         |
|    $m_6$  | bba       | $\circledast\boxdot\boxdot$         |
|    $m_7$  | bbb       | $\circledast\boxdot\circledast$     |



| $E_{007}$ |  Plaintext  |     Glyphtext                       |
|    ----:  | :----------:| :---------------------------------: |
|    $m_0$  | aaa         | $\circledast\circledast\circledast$ |
|    $m_1$  | aab         | $\boxdot\boxdot\boxdot$             |
|    $m_2$  | aba         | $\boxdot\boxdot\circledast$         |
|    $m_3$  | abb         | $\boxdot\circledast\boxdot$         |
|    $m_4$  | baa         | $\boxdot\circledast\circledast$     |
|    $m_5$  | bab         | $\circledast\boxdot\boxdot$         |
|    $m_6$  | bba         | $\circledast\boxdot\circledast$     |
|    $m_7$  | bbb         | $\circledast\circledast\boxdot$     |


We can attempt to give a general description of these forward functions. To do so, let us first find alternative names for the forward functions. We can identify each function by the decimal value represented by the key string.

$$
    {\begin{array}{ll}
    E_0 = E_{000}\\
    E_1 = E_{001}\\
    E_2 = E_{010}\\
    E_3 = E_{011}\\
    E_4 = E_{100}\\
    E_5 = E_{101}\\
    E_6 = E_{110}\\
    E_7 = E_{111}\\
    \end{array}}
$$

The following expression defines the entire family of forward functions:

$$
    {{E_{i}(m_j) = E_{0}(m_{(i+j) \ mod \ 8}) \ where \ 0 \le i \lt 8, \ 0 \le j \lt 8 }}
$$



:warning:

```
The family of functions defined above is cryptographically insecure. Each function
is determinitic,  stateless, and does not make random choices in key selection.
Each function produces the same glyphtext for a given combination of key and plaintext.
Now, assume that an adversary has seen a plaintext and its corresponding glyphtext.
With this signle sample, our adversery will be able to accurately predict the plaintext
for any given glyphtext under the same key, although the adversery has no knowledge of
the key value. This is a total violation of the confidentiality of communication.

To be secure, schemes must incorporate randomness in their design. It should be
computationally infeasible for an adversery to predict even a few bits of plaintext.
This should be true even if the adversery has control over the channel, and can influence
the choice of plaintext or ciphertext.

In the following sections we will see definitions of cryptographic security against
sophisticated attack models. Modern protools are designed to work in the presence
of adversaries who have some control over plaintext and ciphertext traffic over
an insecure channel.

```


### 1.3.2 A Family of Permutations

A permutation is a *bijection*, that is, a *one-to-one onto map* whose domain and range are the same set.

```math
    {\begin{array}{rllll}
    & K & \in & \{0, 1\}^3 & \text{3 bit keys} \\
    & M & \in & \{a, b\}^3 & \text{3 letter plaintext comprised of} \ a\text{'s and } b \text{'s} \\
    & S & \in & \{a, b\}^3 & \text{3 letter output containing} \ a\text{'s and } \ b\text{'s}  \\
    \end{array}}
```

A map

$$
    {\begin{array}{r}
        &\pi: M \rightarrow S
    \end{array}}
$$

is a permutation if for every $m \in M$ there is exactly one $s \in S$ such that $\pi(m) = s$.

We write `Domain`($\pi$) for $M$, and `Range`($\pi$) for $S$.

In addition, the `Domain`($\pi$) = `Range`($\pi$). These are essential properties of a permutation.

A function is bijective if and only if it is invertible. Thus, if $\pi$ is bijective then there is another function $\pi^{-1}$ (the inverse of $\pi$) such that $\pi^{-1}(\pi(m) = m$.

Referring back to [Correctness Requirement for Ciphers (definition 1.1.1)](#xref-def-cipher-correctness) we notice that $Dec_k$ is the inverse of $Enc_k$. Therefore, we conclude that a cipher defines a bijection.

We say that `F` is a family of permutations if `Domain`(F) = `Range`(F), and each $F_k$ is a permutation on this common set.

### 1.4 AES Block Cipher
FIPS 197 is the official publication of Advanced Encryption Standard (AES). It defines three member block ciphers: AES-128, AES-192, and AES-256. Each cipher transforms a block of 128 bits. The numerical suffix indicates the bit length of the associated cryptographic keys. Regardless of the key size, the block size or the length of the data inputs and outputs is 128 bits in each case.

Of course, this technique is simply not feasible when the key space is extremely large. As an example, if the key length is 128 bits (as in AES-128), it is impossible to create $2^{128}$ tables, one for each possible key. AES-128 is a family of $2^{128}$ functions.


### 1.5 Block Cipher Modes of Operation


### 1.6 Eavesdropping Adversary and EVA Security


### 1.7 Chosen Plaintext Attack Security


### 1.8 Chosen Ciphertext Attack Security


### 1.9 Authenticated Encryption with Associated Data


### 1.10 Message Authentication Code (MAC)


### 1.10.1 HMAC



## References

<a id="xref-fips-197-aes"></a>
FIPS 197, Advanced Encryption Standard (AES) https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf.

<a id="xref-ietf-cc20p1305"></a>
ChaCha20 and Poly1305 for IETF Protocols. https://datatracker.ietf.org/doc/html/rfc8439#section-2.3.


<a id="xref-nist-800-38A-block-cipher-modes"></a>
NIST Special Publication 800-38A, 2001 Edition. Recommendation for Block Cipher Modes of Operation. Methods and Techniques.
https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf.


<a id="xref-nist-800-135-rev1-reco-kdf"></a>
NIST SP 800-135, Revision 1. Recommendation for Existing Application-Specific Key Derivation Functions.
https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-135r1.pdf.
