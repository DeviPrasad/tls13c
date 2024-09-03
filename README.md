# Background

This is a pure rust implementation of TLS 1.3 1-RTT client, without client authentication. It is a non-trivial implementation of the TLS client-side protocol. This client has been tested against a handful of TLS 1.3 servers in the wild, including a bunch of big-tech servers, large fintech and government websites, and OpenSSL `s_server` running on localhost. The client has been tested on Mac and Linux boxes, all of which has helped in making the code more robust.

We call this version of the project `tlsc`, obviously meaning a TLS client.

While setting up the secure channel, TLS clients and servers carry out symmetric operations deriving a shared cryptographic state. Understanding the client's behavior naturally leads to an understanding the server's working. This is why we claim `tlsc` is a non-trivial implementation of the protocol.


Given the wide deployment and success of TLS 1.3, it is natural to be curious about its internal design. As a matter of fact, this project grew out of sheer curiosity: How does TLS achieve security? What are the cryptographic primitives used in TLS? Why did the protocol designers use the primitives the way they did? Does Rust ecosystem make it easy to develop a non-trivial TLS client? What are the mathematical underpinnings of the cryptographic schemes used in TLS? Who are the inventors of these cryptographic primitives? Are these ideas reused in other security protocols? And so on.

TLS 1.3 employs a whole host of cryptographic primitives, constructions, and schemes: public key cryptography, symmetric key cryptography (block ciphers and stream ciphers), Elliptic curve Diffie-Hellman key exchange, Digital signature schemes, Message Authentication Code (MAC), Key Derivation Function (KDF), Authenticated Encryption with Associated Data (AEAD), and Hash functions. These protocols are standardized by IETF, and in some cases, by NIST. There is a lot of ground to cover in understanding the design of TLS 1.3.

Mathematics is at the heart of cryptography. We believe it is important to learn some of the basic math used in defining the building blocks. Therefore, in our technical notes, we present mathematical objects, and their properties while also discussing programming details. We refer to textbooks, academic resources, and research papers while describing the protocol design.

The implementation of `tlsc` is based on [RFC 8446](#rfc-8446), IETF's specification of TLS 1.3. Our technical notes must be used in conjunction with the RFC, referring to the Rust code for better understanding. Our goal is to learn cryptography principles without getting lost in too many rabbit holes. That is the primary reason to start with TLS, and get into the details of cryptographic primitives as required.


# The Story of TLS 1.3

The design of TLS 1.3 reinforces the principle that minimalism trumps complexity. It has shown that the composition of a small number of primitives is amenable to formal verification, is more secure, and therefore, produces few surprises in large scale deployment. For the students of Computer Science and Software Engineering, studying the development of TLS 1.3 offers a wealth of insights. Starting from the [draft-00](#draft-00) dated April-2014 to its final stamping as [RFC 8446](#rfc-8446) on August-2018, its evolution is a successful story of collaboration among researchers and practitioners alike.

Researchers used formal verification to prove the correctness of the security model of the record layer. They pointed out strengths and potential weaknesses of different models even before models made their way to the specification. The [informative references](#informative-refs) in RFC 8446 give us an idea of the activity that happened around the protocol design.

Big tech companies lead the implementation and early deployment experience. Cloudflare, Facebook, and Google used their reach to gain experience with the deployment of early versions. Many articles describe interesting details: [apnic](#apnic), [cloudflare](#cloudflare-2016)

A more recent [article](#acm-tls13) presents a great summary of the status as on 2021. It clearly shows that the world has accepted the protocol, and is in fact, benefiting from protocol's security guarantees.


# The Purpose

### Learn the Correct Ways of Using Cryptographic Primitives

### Programming in Rust
One of the reasons for choosing Rust for implementation is its

### Mathematics of Cryptography, and Textbooks

### Real-World Cryptography

### Knowing More about Inventors and Cryptographers




# References
<a id="apnic"></a>
https://blog.apnic.net/2022/08/17/tls-1-3-a-story-of-experimentation-and-centralization/#:~:text=TLS%201.3%20has%20enjoyed%20considerable,ultimately%20deploy%20it%20at%20scale.


<a id="draft-00"></a>
https://datatracker.ietf.org/doc/html/draft-ietf-tls-tls13-00


<a id="cloudflare-2016"></a>
https://blog.cloudflare.com/introducing-tls-1-3/


<a id="informative-refs"></a>
https://datatracker.ietf.org/doc/html/rfc8446#section-12.2


<a id="rfc-8446"></a>
https://datatracker.ietf.org/doc/html/rfc8446


<a id="acm-tls13"></a>
https://dl.acm.org/doi/fullHtml/10.1145/3442381.3450057