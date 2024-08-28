
https://mailarchive.ietf.org/arch/msg/tls/KXzTvSg4z_kpjkioRMk4W2CCLvY/


authenticating every packet - DJB
https://groups.google.com/g/boring-crypto/c/BpUmNMXKMYQ

```
There's a false alarm going around about some new Google crypto code.
This motivates a review of some principles of boring cryptography:

Protocol designers:
1. Split all data into packets sent through the network.
2. Put a small global limit on the packet length (e.g., 1024 bytes).
3. Encrypt and authenticate each packet (with, e.g., crypto_box).

Crypto library designers:
1. Encrypt and authenticate a packet all at once.
2. Don't support "update" interfaces (such as HMAC_Update).
3. Test every small packet size (up to, e.g., 16384 bytes).

The fundamental reason for encrypting and authenticating each packet is
to get rid of forged data as quickly as possible. For comparison, here's
what happens if many packets are concatenated into a large file before
authenticators are verified:

* A single forged packet will destroy an entire file. This is massive
denial-of-service amplification.

* The protocol implementor won't want to buffer arbitrary amounts of
data. To avoid this he'll pass along _unverified_ data to the next
application layer, followed eventually by some sort of failure
notification. This ends up drastically increasing the amount of
code that has to deal with forged data.

...
```
