# Background

This is a pure rust implementation of TLS 1.3 1-RTT client, without client authentication. It is a non-trivial implementation of the TLS client-side protocol. While setting up the secure channel, the TLS client's behavior is symmetric to that of the server. The client and the server carry out symmetric operations deriving a shared cryptographic state. All of this implies that understanding the client's implementation naturally leads to an understanding the server's behavior. This is why we claim this to be a non-trivial implementation.

This client has been tested against a handful of TLS 1.3 servers in the wild, including a bunch of government web sites, big-tech servers, and even OpenSSL's `s_server.` It has been tested on Mac and Linux, all of which has helped in making the client more robust.

We call this version of the project `tlsc`, obviously meaning a TLS client.

Given the wide deployment and success of this protocol, it is natural to be curious about its internal design. As a matter of fact, this project is a product of sheer curiosity: How does TLS achieve security? What are the primitives used in TLS? Why did the protocol designers use the primitives in the way they did? Does Rust ecosystem make it easy to develop a non-trivial TLS client? What are the mathematical ideas underlying the schemes used in TLS? Who are the inventors of these cryptographic primitives? Are these ideas reused in other security protocols?

Not surprisingly, TLS employs a whole host of constructions and schemes: public key cryptography, symmetric key cryptography (block ciphers and stream ciphers), Message Authentication Code (MAC), Key Derivation Function (KDF), Authenticated Encryption with Associated Data (AEAD), and Hash functions. Because Mathematics is at the heart of these building blocks, we do not hesitate to present mathematical objects and their properties along with the practical aspects of their implementation.


The implementation of `tlsc` is based on [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446), IETF's specification of TLS 1.3. Our technical notes must be used in conjunction with the RFC, referring to the Rust code for better understanding. Our goal is to learn cryptography principles without getting lost in too many rabbit holes. That is the primary reason to start with TLS, and get into the details of cryptographic primitives as required.


# The Story of TLS 1.3

The design of TLS 1.3 yet again informs us that minimalism trumps complexity. It demonstrates that the composition of a small number of useful primitives is amenable to formal verification, more secure, and therefore, produces few surprises in large scale deployment. For the students of Computer Science and Software Engineering, studying the development of TLS 1.3 offers a wealth of insights. Starting from the [draft-00](https://datatracker.ietf.org/doc/html/draft-ietf-tls-tls13-00) dated April-2014 to its final stamping as [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) on August-2018, its evolution is a successful story of collaboration among researchers and practitioners alike.

Researchers used formal verification to prove the correctness of the security model of the record layer. They pointed out strengths and potential weaknesses of different models even before models made their way to the specification. The [informative references](https://datatracker.ietf.org/doc/html/rfc8446#section-12.2) in RFC 8446 give us an idea of the activity that happened around the protocol design.

Big tech companies lead the implementation and early deployment experience. Cloudflare, Facebook, and Google used their reach to gain experience with the deployment of early versions. Many articles describe interesting details: [apnic](#apnic), [cloudflare](#cloudflare-2016)

A more recent [article](https://dl.acm.org/doi/fullHtml/10.1145/3442381.3450057) presents a great summary of the status as on 2021. It clearly shows that the world has accepted the protocol, and is in fact, benefiting from protocol's security guarantees.


# The Purpose





# References
<a id="apnic"></a>
https://blog.apnic.net/2022/08/17/tls-1-3-a-story-of-experimentation-and-centralization/#:~:text=TLS%201.3%20has%20enjoyed%20considerable,ultimately%20deploy%20it%20at%20scale.

<a id="cloudflare-2016"></a>
https://blog.cloudflare.com/introducing-tls-1-3/