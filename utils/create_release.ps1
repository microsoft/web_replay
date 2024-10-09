# Copyright (c) Microsoft Corporation.
# Licensed under the BSD-3-Clause license.

$RELEASE_DIR = "web_replay"

New-Item -ItemType Directory -Path $RELEASE_DIR

Copy-Item -Path "bin" -Destination $RELEASE_DIR -Recurse
Copy-Item -Path "utils\set_args.ps1" -Destination $RELEASE_DIR
Copy-Item -Path "utils\remove_args.ps1" -Destination $RELEASE_DIR
Copy-Item -Path "utils\install_certs.ps1" -Destination $RELEASE_DIR
Copy-Item -Path "README.md" -Destination $RELEASE_DIR
Copy-Item -Path "NOTICE.md" -Destination $RELEASE_DIR
Copy-Item -Path "LICENSE" -Destination $RELEASE_DIR

Compress-Archive -Path "$RELEASE_DIR\*" -DestinationPath "$RELEASE_DIR.zip" -Force

Remove-Item -Path $RELEASE_DIR -Recurse
