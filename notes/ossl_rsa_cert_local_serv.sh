#!/bin/bash

openssl genrsa -out dicp-rsa-key.pem 4096

openssl req -new -x509 -key dicp-rsa-key.pem -out dicp-rsa-cert.pem -days 360

# run the openssl server...
openssl s_server -key dicp-rsa-key.pem -cert dicp-rsa-cert.pem -accept 443 -tls1_3 -msg -state -www -debug
