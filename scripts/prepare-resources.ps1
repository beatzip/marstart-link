# Downloads WireGuard-NT and Wintun DLLs into src-tauri/resources (same as CI).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$sdk = Join-Path $root "src-tauri\sdk"
$res = Join-Path $root "src-tauri\resources"
$wgDest = Join-Path $res "wireguard.dll"
$wtDest = Join-Path $res "wintun.dll"

New-Item -ItemType Directory -Force -Path $sdk, $res | Out-Null

if ((Test-Path $wgDest) -and (Test-Path $wtDest)) {
    Write-Host "Resources already present in $res"
    exit 0
}

$wgZip = Join-Path $sdk "wireguard-nt.zip"
$wtZip = Join-Path $sdk "wintun.zip"

Invoke-WebRequest -Uri "https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip" -OutFile $wgZip
Expand-Archive -Path $wgZip -DestinationPath (Join-Path $sdk "wireguard-nt") -Force

Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-0.14.1.zip" -OutFile $wtZip
Expand-Archive -Path $wtZip -DestinationPath (Join-Path $sdk "wintun") -Force

$wg = Get-ChildItem (Join-Path $sdk "wireguard-nt") -Recurse -Filter "wireguard.dll" | Select-Object -First 1
$wt = Get-ChildItem (Join-Path $sdk "wintun") -Recurse -Filter "wintun.dll" | Select-Object -First 1

if (-not $wg) { throw "wireguard.dll not found in SDK extract" }
if (-not $wt) { throw "wintun.dll not found in SDK extract" }

Copy-Item $wg.FullName -Destination (Join-Path $res "wireguard.dll") -Force
Copy-Item $wt.FullName -Destination (Join-Path $res "wintun.dll") -Force

Write-Host "Copied wireguard.dll and wintun.dll to $res"
