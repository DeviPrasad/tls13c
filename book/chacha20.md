### 2.1 Stream Cipher


### 2.2 ChaCha20 Stream Cipher
The inputs to [ChaCha20](#xref-ietf-cc20p1305) are:

- A 256-bit (32 bytes) key
    - treated as a concatenation of eight 32-bit little-endian integers.

- A 96-bit nonce
    - treated as a concatenation of three 32-bit little-endian integers.
    
- A 32-bit block count parameter
    - treated as a 32-bit little-endian integer.

The output is 64 random-looking bytes (512-bit block).

It is clear from the above definition that ChaCha20 internally works like a block cipher in counter mode. Its design includes a 32-bit block counter. 

The block count is a 32-bit parameter, therefore, a single (key, nonce) combination can be used with $2^{32}$ blocks. Given that a block size is 64 bytes, the same (key, nonce) pair can be used to encrypt $2^6 * 2^{32}$ bytes or 256 GB data. (Usually counter zero is used to produce the authentication tag, and therefore, the maximum data size is 256 GB - 64 bytes).

In cases where a single key is used by multiple senders, they should not to use use the same nonces. This can be achieved by dividing the nonce in two parts: the first 32 bits represent the sender, while the other 64 bits come from a counter.

#### Nonce in TLS 1.3
[Section 5.3 of TLS 1.3](#xref-tls1.3-per-rec-nonce) requires peers to derive 96-bit IVs, and to maintain two 64-bit per-record nonces. One of the nonces is used while encrypting messages, and the other for descrypting protected messages. Later when using the counter, it is extended to 96-bits (12 bytes) in big-endian form. Leftmost 32 bits (4 bytes) are padded with zeroes. This 96-bit value is XORed with the actual 96-bit IV to produce the nonce for encryption or decryption of the next message.

In other words, TLS 1.3 follows the advice in [ChaCha20](#xref-ietf-cc20p1305). It is no surprise because the first [proposal](#xref-agl-draft-cc20p1305-tls) to use ChaCha20 and Poly1305 in TLS dates as far back as September 2013. 


## References

<a id="xref-ietf-cc20p1305"></a>
ChaCha20 and Poly1305 for IETF Protocols. https://datatracker.ietf.org/doc/html/rfc8439#section-2.3.


<a id="xref-djb-cc20p1305"></a>
ChaCha, a variant of Salsa20. https://cr.yp.to/chacha/chacha-20080128.pdf.

<a id="xref-agl-draft-cc20p1305-tls"></a>
ChaCha20 and Poly1305 based Cipher Suites for TLS (draft-agl-tls-chacha20poly1305-00). https://datatracker.ietf.org/doc/html/draft-agl-tls-chacha20poly1305-00.

<a id="xref-tls1.3-per-rec-nonce"></a>
The Transport Layer Security (TLS) Protocol Version 1.3. https://www.rfc-editor.org/rfc/rfc8446.html#section-5.3