#!/usr/bin/env bash
set -euo pipefail
this_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
set -x

# root key and certificate
openssl ecparam -name prime256v1 -genkey -noout -out "$this_dir"/root.key.pem

openssl req -new -x509 \
	-key "$this_dir"/root.key.pem \
	-out "$this_dir"/root.cert.pem \
	-days 10000 \
	-subj "/CN=Root CA" \
	-addext  "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign,cRLSign" \
	-addext "subjectKeyIdentifier=hash"

# intermediate certifcate
openssl ecparam -name prime256v1 -genkey -noout -out "$this_dir"/int.key.pem

openssl req -new \
	-key "$this_dir"/int.key.pem \
	-out "$this_dir"/int.csr.pem \
	-subj "/CN=Intermediate CA"

openssl x509 -req \
	-in "$this_dir"/int.csr.pem \
	-CA "$this_dir"/root.cert.pem \
	-CAkey "$this_dir"/root.key.pem \
	-CAcreateserial \
	-out "$this_dir"/int.cert.pem \
	-days 10000 \
	-extfile "$this_dir"/v3ext.int.cnf \
	-extensions v3_ca

# leaf certificate
openssl req -new \
	-key "$this_dir"/key.priv.pem \
	-out "$this_dir"/leaf.csr.pem \
	-subj "/CN=CoRIM Signer"

openssl x509 -req \
	-in "$this_dir"/leaf.csr.pem \
	-CA "$this_dir"/int.cert.pem \
	-CAkey "$this_dir"/int.key.pem \
	-CAcreateserial \
	-out "$this_dir"/leaf.cert.pem \
	-days 10000 \
	-extfile "$this_dir"/v3ext.leaf.cnf \
	-extensions v3_leaf

# Regenerates root.key.pem, int.key.pem, and all *.cert.pem. key.priv.pem (leaf signing key) is preserved.
