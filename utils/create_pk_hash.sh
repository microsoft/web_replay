# Copyright (c) Microsoft Corporation.
# Licensed under the BSD-3-Clause license.

openssl x509 -noout -pubkey -in $1 | \
openssl pkey -pubin -outform der | \
openssl dgst -sha256 -binary | \
base64
