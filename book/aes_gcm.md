
### AES

AES block size is ony 128 bits, regardless if we are using AES 128 or AES 256.

AES block size is ony 128 bits, and AES-GCM nonces are 12 bytes. 

The authentication tag size is 128 bits (16 bytes) whether AES_128_GCM or AES_256_GCM is used.


                        Key    Nonce   Tag     Block 
        AES_128_GCM     128    96      128     128

        AES_256_GCM     256    96      128     128


TLS 1.3 section 5.3 shows how to construct per-record nonce.


GCM is defined for block ciphers with a block size of 128 bits.

### AES-CTR Mode
ES-CTR has many properties that make it an attractive encryption algorithm for in high-speed networking.  AES-CTR uses the AES block cipher to create a stream cipher.  Data is encrypted and decrypted by XORing with the key stream produced by AES encrypting sequential counter block values.


AES-CTR uses the only AES encrypt operation (for both encryption and decryption), making AES-CTR implementations smaller than implementations of many other AES modes.

When used correctly, AES-CTR provides a high level of confidentiality.  Unfortunately, AES-CTR is easy to use incorrectly. Being a stream cipher, any reuse of the per-packet value, called theIV, with the same nonce and key is catastrophic.  An IV collision immediately leaks information about the plaintext in both packets.

For this reason, it is inappropriate to use this mode of operation with static keys.  Extraordinary measures would be needed to prevent reuse of an IV value with the static key across power cycles.  To be safe, implementations MUST use fresh keys with AES-CTR.  The Internet Key Exchange (IKE) [IKE] protocol can be used to establish fresh keys.  IKE can also provide the nonce value.

With AES-CTR, it is trivial to use a valid ciphertext to forge other (valid to the decryptor) ciphertexts.  Thus, it is equally catastrophic to use AES-CTR without a companion authentication function.  Implementations MUST use AES-CTR in conjunction with an authentication function, such as HMAC-SHA-1-96 [HMAC-SHA].

To encrypt a payload with AES-CTR, the encryptor partitions the
plaintext, PT, into 128-bit blocks.  The final block need not be 128
bits; it can be less.

    PT = PT[1] PT[2] ... PT[n]

Each PT block is XORed with a block of the key stream to generate the
ciphertext, CT.  The AES encryption of each counter block results in
128 bits of key stream.  The most significant 96 bits of the counter
block are set to the nonce value, which is 32 bits, followed by the
per-packet IV value, which is 64 bits.  The least significant 32 bits
of the counter block are initially set to one.  This counter value is
incremented by one to generate subsequent counter blocks, each
resulting in another 128 bits of key stream.  The encryption of n
plaintext blocks can be summarized as:

    CTRBLK := NONCE || IV || ONE
    FOR i := 1 to n-1 DO
        CT[i] := PT[i] XOR AES(CTRBLK)
        CTRBLK := CTRBLK + 1
    END
    CT[n] := PT[n] XOR TRUNC(AES(CTRBLK))

The AES() function performs AES encryption with the fresh key.

The TRUNC() function truncates the output of the AES encrypt
operation to the same length as the final plaintext block, returning
the most significant bits.

Decryption is similar.  The decryption of n ciphertext blocks can be summarized as:

    CTRBLK := NONCE || IV || ONE
    FOR i := 1 to n-1 DO
        PT[i] := CT[i] XOR AES(CTRBLK)
        CTRBLK := CTRBLK + 1
    END
    PT[n] := CT[n] XOR TRUNC(AES(CTRBLK))


#### Block Size

The AES has a block size of 128 bits (16 bytes).  As such, when using AES-CTR, each AES encrypt operation generates 128 bits of key stream.  AES-CTR encryption is the XOR of the key stream with the plaintext.  AES-CTR decryption is the XOR of the key stream with the ciphertext.  If the generated key stream is longer than the plaintext or ciphertext, the extra key stream bits are simply discarded.  For this reason, AES-CTR does not require the plaintext to be padded to a multiple of the block size.  

In order to provide traffic flow confidentiality, sender MAY include an arbitrary-length run of zero-valued bytes the plaintext after the type field as specified in section 5.2, "Record Payload Protection". The field is named `zeroes` 

    struct {
          opaque content[TLSPlaintext.length];
          ContentType type;
          uint8 zeros[length_of_padding];
      } TLSInnerPlaintext;





Using a sequence number ensures that the same nonce is never used twice with the same key. It also avoids the overhead of having to transmit a nonce over the wire, saving numerous octets per record.

[RFC 5084]
The Galois/Counter Mode (GCM) is specified in [GCM].  GCM is a generic authenticated encryption block cipher mode.  GCM is defined for use with any 128-bit block cipher, but in this document, GCM is used with the AES block cipher.

AES-GCM has four inputs: an AES key, an initialization vector (IV), a plaintext content, and optional additional authenticated data (AAD). AES-GCM generates two outputs: a ciphertext and message


authentication code (also called an authentication tag).  To have a common set of terms for AES-CCM and AES-GCM, the AES-GCM IV is referred to as a nonce in the remainder of this document.

The nonce is generated by the party performing the authenticated encryption operation.  Within the scope of any authenticated- encryption key, the nonce value MUST be unique.  That is, the set of nonce values used with any given key MUST NOT contain any duplicate values.  Using the same nonce for two different messages encrypted with the same key destroys the security properties.

AAD is authenticated but not encrypted.  Thus, the AAD is not included in the AES-GCM output.  It can be used to authenticate plaintext packet headers.  In the CMS authenticated-enveloped-data content type, authenticated attributes comprise the AAD.


The "seal" and "open" operations are atomic - an entire message must be encrypted or decrypted in a single call. Large messages may have to be split up in order to accommodate this. When doing so, be mindful of the need not to repeat nonces and the possibility that an attacker could duplicate, reorder or drop message chunks. 


## TLS 1.3

In TLS 1.3, cipher suites only specify the block cipher and hash function used, such as TLS_AES_128_GCM_SHA256. The key exchange and authentication algorithms are negotiated separately.

###  AES-CTR Mode
The IV is a unique value within an invocation of the authenticated encryption function. In TLS 1.3, AEAD is invoked when the confidentiality of a new handshake message or data record is to be protected. This is the plaintext data represented by TLSInnerPlaintext structure shown above. Further, in order to protect data integrity as well as ptove authenticity, AEAD uses other fields of TLSciphertext staructure as additional data (AD). 

Deterministic Construction as descsribed in section 8.2.1 of NIST Special Publication 800-38D, 


## References

Real-World Cryptography.
Chapter 4 - Autheticated Encryption, Sec 4.5.2, The AES-GCM AEAD, page 76.
David Wong.


Understanding Cryptography.
Chapter 5 - More About Block Ciphers, Sec 5.1.6, Galois Counter Mode (GCM), page 134.
Christof Paar Jan Pelz.

Authenticated Encryption with Additional Data.

https://commondatastorage.googleapis.com/chromium-boringssl-docs/aead.h.html


Recommendation for Block Cipher Modes of Operation. Methods and Techniques.
https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf


https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf


Using Advanced Encryption Standard (AES) Counter Mode With IPsec Encapsulating Security Payload (ESP), https://www.ietf.org/rfc/rfc3686.txt, January 2004



Usage Limits on AEAD Algorithms
https://www.ietf.org/archive/id/draft-irtf-cfrg-aead-limits-08.html
draft-irtf-cfrg-aead-limits-08. Expires: 3 October 2024.
F. Günthe, M. Thomson, and C. A. Wood.

