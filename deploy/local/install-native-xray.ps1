[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$runtimeRoot = Join-Path $projectRoot ".local"
$downloadRoot = Join-Path $runtimeRoot "downloads"
$installRoot = Join-Path $runtimeRoot "xray-26.3.27"
$archive = Join-Path $downloadRoot "Xray-windows-64.zip"
$expectedSha256 = "D004C39288CE9ADA487C6F398C7C545F7D749E44BDFDD59DBC9F865AFBA4E1AD"
$downloadUrl = "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-windows-64.zip"

if (Test-Path -LiteralPath (Join-Path $installRoot "xray.exe") -PathType Leaf) {
    Write-Output "native_xray=already-installed"
    exit 0
}

New-Item -ItemType Directory -Path $downloadRoot -Force | Out-Null
if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
    Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $archive
}
$actualSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
if ($actualSha256 -ne $expectedSha256) {
    throw "Official Xray archive checksum mismatch."
}
if (Test-Path -LiteralPath $installRoot) {
    throw "Partial Xray installation already exists at $installRoot."
}
Expand-Archive -LiteralPath $archive -DestinationPath $installRoot
& (Join-Path $installRoot "xray.exe") run -test -config (Join-Path $projectRoot "deploy\local\xray-control-plane.json")
if ($LASTEXITCODE -ne 0) { throw "Xray rejected the local fail-closed configuration." }

Write-Output "native_xray=installed"
Write-Output "xray_version=26.3.27"
Write-Output "archive_sha256=$actualSha256"
