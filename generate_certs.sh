#!/bin/bash

# Exit on error
set -e

mkdir -p certs
cd certs

echo "Generating Root CA..."
# Generate CA private key
/usr/bin/openssl genrsa -out ca.key 2048
cat > ca.ext << EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]
C = US
ST = CA
O = NullStrike
CN = NullStrikeRootCA

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
EOF

# Generate CA certificate
/usr/bin/openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -config ca.ext
echo "Generating Server Certificate..."
# Generate server private key
/usr/bin/openssl genrsa -out server.key 2048
# Generate server CSR
/usr/bin/openssl req -new -key server.key -out server.csr -subj "/C=US/ST=CA/O=NullStrike/CN=127.0.0.1"

# Create extension file for server (Subject Alternative Name is required by Rust's TLS libraries)
cat > server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
IP.1 = 127.0.0.1
DNS.1 = localhost
EOF

# Sign server CSR with CA
/usr/bin/openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256 -extfile server.ext

echo "Generating Client Certificate..."
# Generate client private key
/usr/bin/openssl genrsa -out client.key 2048
# Generate client CSR
/usr/bin/openssl req -new -key client.key -out client.csr -subj "/C=US/ST=CA/O=NullStrike/CN=NullStrikeAgent"
cat > client.ext << EOF
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
EOF

# Sign client CSR with CA
/usr/bin/openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256 -extfile client.ext

echo "Cleaning up..."
rm *.csr *.ext *.srl

echo "Certificates generated successfully in certs/ directory!"
