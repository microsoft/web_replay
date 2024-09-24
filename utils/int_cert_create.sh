# Copyright (c) Microsoft Corporation.
# Licensed under the BSD-3-Clause license.

openssl req -new -nodes -out int_cert.csr -newkey rsa:4096 -keyout int_key.pem -subj "/CN=Web Replay Intermediate/O=Web Replay"

cat > int_cert.v3.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:TRUE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign
EOF

openssl x509 -req -in int_cert.csr -CA root_cert.pem -CAkey root_key.pem -out int_cert.pem -days 10000 -sha256 -extfile int_cert.v3.ext

rm int_cert.csr
rm int_cert.v3.ext
