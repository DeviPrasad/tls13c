#!/bin/bash

# produce small certs of secp256r1; this is called prime256v1 in openssl
# good for testing the handshake protocol using small buffers to read the messages.
openssl ecparam -name prime256v1 -genkey -noout -out dicp-key.pem

# if you are interested in the public key...
openssl ec -in dicp-key.pem -pubout -out dicp-public-key.pem

# the public cert for use in our local server.
openssl req -new -x509 -key dicp-key.pem -out dicp-cert.pem -days 360

# run the openssl server...
openssl s_server -key dicp-key.pem -cert dicp-cert.pem -accept 443 -tls1_3 -msg -state -www -debug
