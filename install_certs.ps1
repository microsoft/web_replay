# Copyright (c) Microsoft Corporation.
# Licensed under the BSD-3-Clause license.

$MyInvocation.MyCommand.Path | Split-Path | Push-Location

$Rootparams = @{
    FilePath = '.\certs\root_cert.pem'
    CertStoreLocation = 'Cert:\LocalMachine\Root'
}

$Intparams = @{
    FilePath = '.\certs\int_cert.pem'
    CertStoreLocation = 'Cert:\LocalMachine\CA'
}

Import-Certificate @Rootparams
Import-Certificate @Intparams
