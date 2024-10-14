# Copyright (c) Microsoft Corporation.
# Licensed under the BSD-3-Clause license.

param(
    [Parameter(Mandatory=$true)]
    [string]$exe
)

Set-Item -Path Env:CGO_CFLAGS  -Value "-I$(Get-Location)\include"
Set-Item -Path Env:CGO_LDFLAGS -Value "-L$(Get-Location)\bin"

if ($exe -eq "web_replay") {
    Write-Output "Building web_replay..."
    go build -o bin\web_replay.exe .\src\wpr.go
} elseif ($exe -eq "archive") {
    Write-Output "Building archive..."
    go build -o bin\archive.exe .\src\httparchive.go
} else {
    Write-Output "Usage: .\build.ps1 [web_replay|archive]"
}
