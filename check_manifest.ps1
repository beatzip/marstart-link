param($exePath)
$bytes = [System.IO.File]::ReadAllBytes($exePath)
$text = [System.Text.Encoding]::ASCII.GetString($bytes)

$found = $false

$str = "requireAdministrator"
$pos = $text.IndexOf($str)
if ($pos -ge 0) {
    $found = $true
    Write-Host "FOUND: $str at offset $pos"
}

$str = "asInvoker"
$pos = $text.IndexOf($str)
if ($pos -ge 0) {
    $found = $true
    Write-Host "FOUND: $str at offset $pos"
}

$str = "trustInfo"
$pos = $text.IndexOf($str)
if ($pos -ge 0) {
    $found = $true
    Write-Host "FOUND: $str at offset $pos"
}

$str = "requestedExecutionLevel"
$pos = $text.IndexOf($str)
if ($pos -ge 0) {
    $found = $true
    Write-Host "FOUND: $str at offset $pos"
}

if (-not $found) {
    Write-Host "NOT FOUND: No manifest strings in binary" -ForegroundColor Red
}
