#!/bin/bash

mv ../certs/certGen enduser.p12
openssl pkcs12 -clcerts -nokeys -in enduser.p12 -out enduser.crt
openssl crl -inform DER -in ../revokedlist.crl -outform PEM -out crl.pem
openssl crl -in crl.pem -CAfile intermediate.cert.pem
cat ca-chain.cert.pem crl.pem > crl_chain.pem
openssl verify -crl_check -CAfile crl_chain.pem enduser.crt