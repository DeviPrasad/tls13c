## Cryptographic Hash Functions

In the paper which introduced [HMAC scheme](#key-hash-funcs-msg-auth-bellare) in 1996, the authors discuss some of the basic properties of hash functions. They identify *collision resistance* as one of the important properties of keyless hash functions. The authors observe that there are additional properties of hash functions that are usually not mentioned explicitly, which nevertheless permit their use in other schemes. We quote parts of the two paragraphs here:

<blockquote>
In addition to the basic collision-resistance property, cryptographic hash functions are usually designed to have some randomness-like properties, like good mixing properties, independence of input/output, unpredictability of the output when parts of the input are unknown, etc. Not only do these properties help in making it harder to find collisions, but also they help to randomize the input presented to the signature algorithm (e.g., RSA) as usually required for the security of these functions.

<br>

It is the combination of these properties attributed to cryptographic hash functions that make them so attractive for many uses beyond the original design as collision-resistant functions. These functions have been proposed as the basis for pseudorandom generation, block ciphers, random transformation, and message authentication codes.
</blockquote>


## Hash and Message Authentication Code (MAC)
SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by the United States National Security Agency (NSA) and first published in 2001.[3][4] They are built using the Merkle–Damgård construction, from a one-way compression function itself built using the Davies–Meyer structure from a specialized block cipher.

<a id="key-hash-funcs-msg-auth-bellare"></a>
Keying Hash Functions for Message Authentication. https://cseweb.ucsd.edu/~mihir/papers/kmd5.pdf.