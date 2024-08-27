### Authenticated Encryption
Insecure public networks make it easier to manipulate ciphertext appearing on the communication channels. Modern cryptography favors composing symmetric encryption and authentication in one scheme. 

The definition of authenticated-encryption is met by encrypt-then-MAC and not met by MAC-then-encrypt.

Padding Oracle Attack (1998, 2002)
Lucky13 attack on SSL (2013)

The advocates of encrypt-then-MAC insist that the "ciphertext" which is authenticated (or MACed) should include IV/nonce, message sequence number, the message type identifier, the protocol version, and any element relevant to the security context.

In TLS 1.3, peers derive traffic keys and IV on their own. The initial secrets - salt and input key material - required for key derivation is obtained via ECDHE. By the end of the key exchange phase, which includes CleintHello and ServerHello messages, both parties will have adequate information required to derive correct traffic keys and IV. It is also important to note that the server mixes the current record number with IV while encrypting the message record. Client and server maintain record seuqence numbers in a lockstep manner.


1. Adverseries *should not* be able to derive traffic keys even if they read ClientHello and ServerHello (plaintext) messages on the wire (in transit).

2. Peers should be able to derive the correct keys. In most cases, the 

3. The integrity of the ciphertext must be protected.

4. MAC should not leak or reveal any information about the plaintext.



Moxie emphasizes the importance of *not using* MAC-then-encrypt (or Authenticate-then-encrypt) in an a blog post called "The Cryptographic Doom Principle" (dated December 13, 2011).  


### Authenticated Encryption with Associated Data

The notion of AEAD was formalized by Rogaway


