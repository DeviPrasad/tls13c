## DICP - Part 1

### Background
Virtually every online financial transaction is protected by Transport Layer Security (TLS). Open Banking standards across the globe make TLS version 1.2 or above mandatory for participating entities. TLS is undoubtedly one of the most widely deployed internet security protocol. More recent messaging protocol, MLS (RFC 9420, section-16.1), recommends all MLS messages to be transmitted over TLS 1.3.


### AEAD
Authenticated Encryption with Associated Data (AEAD) [Rog02] has emerged as being the right cryptographic tool for building secure channels. AEAD provides both confidentiality and integrity guarantees for data.


### Stateful AEAD
[Requirements on AEAD Algorithm Specifications](https://datatracker.ietf.org/doc/html/rfc5116)

An Authenticated Encryption algorithm MAY incorporate internal state information that is maintained between invocations of the encrypt operation, e.g., to allow for the construction of distinct values that are used as internal nonces by the algorithm.  An AEAD algorithm of this sort is called stateful.  This method could be used by an algorithm to provide good security even when the application inputs zero-length nonces.

### AEADs and Secure Channel
In [Data Is a Stream: Security of Stream-Based Channels](https://eprint.iacr.org/2017/1191.pdf), Marc Fischlin et.al.,
note that while AEAD provides both confidentiality and integrity guarantees for data, on its own, AEAD does not constitute a secure channel. For example, in most practical situations, a secure channel should provide more than simple encryption of messages, but also guarantee detection of (and possibly recovery from) outof-order delivery and replays of messages.


### The State Machine

In part 1 we will consider the implementation of a TLS 1.3 client program. We call this version of the client program *tlsc*. In TLS 1.3 parlance, *tlsc* implements 1-RTT handshake using ECDHE key exchange mode without client authentication. This characterization gives a specific structure to the interactions between *tlsc* and a TLS 1.3 compliant server. To see the shape of the interaction, refer to Figure 1 on page 11 of RFC 8446. We will also use the state machines `A.1. Client` (page 120) and `A.2. Server` (page 121) in Appendix A.



    Client                              Server

    <Key Exchange>
        ClientHello
            + key_share
            + signature_algorithms
                            -------->
                                        <Key Exchange>
                                            ServerHello
                                                + key_share

                                        <Server Params>
                                            {EncryptedExtensions}

                                        <Auth>
                                            {Certificate}
                                            {CertificateVerify}
                                            {Finished}
                            <--------

    <Auth>
        {Finished}

    <App>
    [Application Data]    <------->     [Application Data]

`Figure 1 - Shape of 1-RTT Handshake without Client Authentication.`

While reading the diagram imagine that time progresses vertically downward and interaction flows in the direction of arrows.

In presenting the diagram above, we have reused the notational convention from RFC 8446 with one augmentation.

1. `+` indicates important extensions sent in the message.
2. `{}` shows messages protected using keys derived from a `[sender]_handshake_traffic_secret`.
3. `[]` indicates messages protected using keys derived from `[sender]_application_traffic_secrete_N`.
4. `<>` names a phase or a sub-protocol. This is our own notation; this is not from RFC 8446.


Figure 1 shown above is a simplifiesd version of Figure 1 from the RFC. We leave out *pre-shared key (PSK)* mode, and authentication messages, Certificate and CertificateVerify, on the client side.


In this document (`DICP - Part 1`), we will study the technical aspects of implementing the interactions shown in Figure 1. We will delve into the details of various cryptographic primitives used in each step of the interaction. We will try to reason why TLS 1.3 chooses to use crytographic constructions in the fashion it does. We will also try to clarify and elaborate aspects where the text in the RFC is eiher cryptic or is not too helpful.


### The Handshake Protocol
The handshake (sub)protocol is the most important part of TLS. Undoubtedy, the designers spent significant effort in improving its efficiency compared to TLS 1.2. Most of the security guarantees of TLS is deined by the handshake protocol. Section 4 of RFC 8446 (about 54 pages of text) is entitely dedicated for describing the messages and interactions constituting handshake protocol. Even the appendices in the RFC discuss, at length, the security aspects of the handshake protocol.

### Key Exchange

Within the handshake protocol, *Key Exchange* is the first phase. In Figure 1 above, this includes two messages:

1. ClientHello
    - the very first message of the protocol.
    - describes cryptographic primitives and algorithms the client is prepared to use in this session.
    - includes one or more ephemeral public keys for elliptic-curve Diffie-Hellman exhange.
    - includes a 32 byte random number indicating client's session freshness.

2. ServerHello.
    - the last/final plaintext message of the handshake protocol.
    - indicates the cryptographic primitives and algorithms the server has accepted.
    - includes server's public key for elliptic-curve Diffie-Hellman exhange.
    - includes a 32 byte random number indicating server's session freshness.

At the end of key exchange, the client and server establish a set of shared secrets used for encrypting (protecting) messages that follow. In addition, the client and server agree upon the cryptographic algorithms (aka ciphersuite) which will be in force for the rest of the session.


### Server Parameters
This message immediately follows ServerHello, and it indicates server's preferences. The server may indicate that the client needs to authenticate (using client's certificate)



### ClientHello

![client_hello_layout](./images/client_hello_layout.jpg)


### ServerHello

![server_hello_layout](./images/server_hello_layout.jpg)


### Authentication
indicates that server authentication uses three messages: Certificate, CertificateVerify, and Finished.


### Protecting Confidentiality, Integrity, and Authenticity of TLS traffic

Section 5.2, page 89 of RFC 8446 presents two type definitions for protected data records. We reproduce the types here with minor notational embellishments. For example, we indicate position of each field relative to the beginning of the data structure. This comes handy while writing constraints on field-lengths. They are also useful in relating the sizes of the components of plaintext and ciphertext. We can eaily turn such specifications into assertions in the Rust progam.

    struct {
        0:1    - ContentType opaque_type = application_data; /* val u8 = 23 */
        1:2    - ProtocolVersion legacy_record_version = TLS_V1.2; /* val u16 = 0x0303 */
        3:2    - uint16 length; /* val u16 where 21 < value < 2^14+256; val aka CL */
        5:CL   - opaque aead_ct_record[TLSCipherText.length]; /* opaque[CL]*/
    } TLSCiphertext; /* thus, sizeof(TLSCiphertext) = 5+CL */


To get a better picture, we will turn the above data definitions into a horizontal layout, as a sequence of bytes, showing byte offsets of different fields.


### TlsInnerPlaintext
This structure holds the plaintext whoch is to be protected. The plaintext may be a handshake message fragment or raw bytes of the application data. It holds handshake message in the authentication phase, and subsequently, post-handshake, it holds application data exchanged by the peers.


    struct {
        0:PL      - opaque content[TLSPlaintext.length]; /* opaque[PL] */
        PL:1      - ContentType type; /* val u8 = 22 if handshake and 23 if application_data */
        PL+1:ZL   - uint8 zeroes[ZL]; /* ZL == CL-(PL+1)-16 */
    } TLSInnerPlaintext; /* thus, sizeof(TLSInnerPlaintext) = IPL == PL+1+ZL == CL-16 */

In the following discussion we will use PL to mean the size of plaintext, in bytes. For brevity, we use CT for ContentType.

In TLSInnerPlaintext, the first field named `content` holds the plaintext bytes. The size of this array is PL (bytes). TLS does not allow zero length `content` field for handshake and alert messages.

The next field `type` holds the content type of the plaintext record. It denotes the `ContentType` of the plaintext in `content` field. CT will have different values depending on the message or data being protected. Thus,

        CT = 21 when plaintext is an alert message,
        CT = 22 when plaintext is one of the following TLS handshake messages
                alert,
                new_session_tcket,
                encrypted_extensions,
                certificate,
                certificate_verify,
                finished,
        and
        CT = 23 when the plaintext is application specific data (i.e, HTTP request or response payload).

TLS 1.3 allows encrypted records to be padded with zeroes as long as the total size of TLSInnerPlaintext record doesn't exceed 2^14 + 1 bytes. When the sender inflates the size of an encrypted record, observers cannot tell the actual size of the plaintext. It is obvious padding increases record size, and may adversely impact overall performance.

Section 5.4 of RFC 8446 describes many aspects of record padding. In our tests, we will see that most HTTP servers do not pad either handshake records or application data records.

The following diagram shows the strucure of TLSInnerPlaintext without padding zeroes, which is the most common case.


                    0    1    2    3    4                              PL   PL+1
                    +----+----+----+----+--/-**-**-**-/-+----+----+----+----+
                    |       Handshake Message or Application Data      | CT |
                    +----+----+----+----+--/-**-**-**-/-+----+----+----+----+
                    <------------------- Plaintext ------------------->|    |
                                        (PL bytes)

                    |<----------------------------------------------------->|
                                        TlsInnerPlaintext
                                        (PL+1 bytes)


                              TlsInnerPlaintext without padding


TlsInnerPlaintext with arbitrary zero padding at the end of the data block may be visualized thus:


        0    1    2    3    4                              PL   PL+1              PL+1+ZL
        +----+----+----+----+--/-**-**-**-/-+----+----+----+----+-***-/**-**-**/--+
        |       Handshake Message or Application Data      | CT |  padding zeroes |
        +----+----+----+----+--/-**-**-**-/-+----+----+----+----+-***-/**-**-**/--+
        <------------------- Plaintext ------------------->|    |<- Optional Pad ->
                            (PL bytes)                               (ZL bytes)

        |<----------------------------------------------------------------------->|
                                    TlsInnerPlaintext


                    TlsInnerPlaintext with arbitray-sized zero padding



### TlsCiphertext
TLS 1.3 employs only Authenticated Encryption with Associated Data (AEAD) ciphers. AEADs simultaneously protect confidentiality of the plaintext, and the authenticity and integrity of ciphertext. In other words, with the AEADs supported by TLS 1.3, one will not be able to learn about the plaintext or the encryption key even if one has access to all ciphertexts exchanged by the peers. At the same time, AEAD ciphers will be able to detect if either ciphertext or the MAC has been tampered or altered in transit. Practical AEADs combine a secure cipher with a strong MAC. Their composition has been proved to provide highese levels of security.

TLS 1.3 defines 5 AEAD algorithms for record protection:

        AES_128_GCM         - compliant application MUST implement this AEAD algorithm.
        AES_256_GCM         - compliant application SHOULD implement this AEAD algorithm.
        CHACHA20_POLY1305   - compliant application SHOULD implement this AEAD algorithm.
        AES_128_CCM
        AES_256_CCM

In `tlsc`, we support the first three algorithms from this list which includes the mandatory AES_128_GCM.



        0    1    2    3    4    5    6    7                          5+IPL                 5+CL
        +----+----+----+----+----+----+----+--/-**-**-**-/--+----+----+----+--/-*-*-/-+----+
        | 23 | 0x0303  |    CL   |                                    |         MAC        |
        +----+----+----+----+----+----+----+--/-**-**-**-/--+----+----+----+--/-*-*-/-+----+
        <--- Additional Data --->|<-- Encrypted  TlsInnerPlainText -->|<-- AEAD Auth TAG -->

        |<---------------------->|<------------------------------------------------------->|
                AAD                                   AEAD output
            (5 bytes)                                (CL bytes)
            plaintext                                ciphertext



### Key Derivation
The server processes the ClientHello message and determines the ciphersuite for the session. The server responds with the ServerHello message which includes its *key share*, which is server's ephemeral Diffie-Hellman share. In `tlsc`, ClientHello contains two shares, each in an EC group: X25519 and secp256r1. These are the only two `supported_groups` in `tlsc`.


![key_schedule](./images/key_schedule.jpg)