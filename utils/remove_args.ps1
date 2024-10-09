# Copyright (c) Microsoft Corporation.
# Licensed under the BSD-3-Clause license.

$browser = "Microsoft Edge"

if ($ARGS.Length -gt 0) {
    switch ($ARGS[0]) {
        "edgedev" {
            $browser = "Microsoft Edge Dev"
        }
        "edgebeta" {
            $browser = "Microsoft Edge Beta"
        }
        "edgecanary" {
            $browser = "Microsoft Edge Canary"
        }
        "chrome" {
            $browser = "Google Chrome"
        }
    }
}

$WshShell = New-Object -ComObject ("WScript.Shell")

$ShortcutPath = "$($env:APPDATA)\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\$browser.lnk"

if (-not (Test-Path $ShortcutPath)) {
    exit 1
}

$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.Arguments = ""
$Shortcut.Save()

exit
