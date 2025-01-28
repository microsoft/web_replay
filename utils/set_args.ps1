# Copyright (c) Microsoft Corporation.
# Licensed under the BSD-3-Clause license.

if ($ARGS[0] -eq $null) {exit 1}

$browser = "edge"

if ($ARGS[0] -eq "web_replay") {
    if ($ARGS[1] -eq $null) {exit 1}
    if ($ARGS[2] -eq $null) {exit 1}
    if ($ARGS[3] -eq $null) {exit 1}
    if ($ARGS[4] -ne $null) {$browser = $ARGS[4]}

    $HostHTTP = "$($ARGS[1]):$($ARGS[2])"
    $HostHTTPS = "$($ARGS[1]):$($ARGS[3])"

    $Arguments = "--host-resolver-rules=`"MAP *:80 $HostHTTP,MAP *:443 $HostHTTPS`""
} elseif ($ARGS[0] -eq "live") {
    if ($ARGS[1] -eq $null) {exit 1}
    if ($ARGS[2] -ne $null) {$browser = $ARGS[2]}

    $Arguments = "--log-net-log=$($ARGS[1]) --disable-quic"
} else {
    exit 1
}

switch ($browser) {
    "edge" {
        $browser = "Microsoft Edge"
    }
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

$WshShell = New-Object -ComObject ("WScript.Shell")

$ShortcutPath = "$($env:APPDATA)\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\$browser.lnk"

if (-not (Test-Path $ShortcutPath)) {
    exit 1
}

$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.Arguments = $Arguments
$Shortcut.Save()

exit
