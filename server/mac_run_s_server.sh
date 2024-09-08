#!/bin/bash

export PATH=/usr/local/opt/openssl@3/bin/openssl:$PATH

# run the openssl server...
openssl s_server -key dicp-rsa-key.pem -cert dicp-rsa-cert.pem -accept 44444 -tls1_3 -msg -state -WWW 
