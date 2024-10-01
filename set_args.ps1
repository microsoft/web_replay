# Copyright (c) Microsoft Corporation.
# Licensed under the BSD-3-Clause license.

if ($ARGS[0] -eq $null) {exit 1}
if ($ARGS[1] -eq $null) {exit 1}
if ($ARGS[2] -eq $null) {exit 1}

$browser = "Microsoft Edge"

if ($ARGS.Length -gt 3) {
    switch ($ARGS[3]) {
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

$HostHTTP = "$($ARGS[0]):$($ARGS[1])"
$HostHTTPS = "$($ARGS[0]):$($ARGS[2])"

$ShortcutPath = "$($env:APPDATA)\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\$browser.lnk"

if (-not (Test-Path $ShortcutPath)) {
    exit 1
}

$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.Arguments = "--host-resolver-rules=`"MAP *:80 $HostHTTP,MAP *:443 $HostHTTPS`""
$Shortcut.Save()

exit
