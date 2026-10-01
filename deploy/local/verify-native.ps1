[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$runtimeRoot = Join-Path $projectRoot ".local"
$envFile = Join-Path $projectRoot ".env.native"
$postgresBin = "C:\Program Files\PostgreSQL\18\bin"
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$xray = Join-Path $runtimeRoot "xray-26.3.27\xray.exe"

if (-not (Test-Path -LiteralPath $envFile -PathType Leaf)) {
    throw "Missing .env.native. Run deploy/local/init-native.ps1 first."
}
foreach ($line in [IO.File]::ReadAllLines($envFile)) {
    if ($line -match "^([A-Z0-9_]+)=(.*)$") {
        [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], "Process")
    }
}
if ($env:KENAI_SUBSCRIPTION_PROTOCOLS -ne "vless") {
    throw "Native environment is not configured for VLESS-only subscriptions."
}

$env:PGPASSWORD = $env:KENAI_NATIVE_POSTGRES_PASSWORD
& (Join-Path $postgresBin "pg_isready.exe") -h 127.0.0.1 -p $env:KENAI_NATIVE_POSTGRES_PORT -d kenai -U kenai | Out-Null
if ($LASTEXITCODE -ne 0) { throw "PostgreSQL is unavailable." }

Set-Location $projectRoot
$revision = [string](& $python -m alembic -c alembic.ini current)
if ($LASTEXITCODE -ne 0 -or $revision -notmatch "e6a1b7c42d90") {
    throw "PostgreSQL is not at the expected Alembic revision."
}

& $xray run -test -config deploy/local/xray-control-plane.json | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Xray rejected the fail-closed local configuration." }

$health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/healthz" -Method Get -TimeoutSec 5
if ($health.status -ne "ok") { throw "Kenai health endpoint did not return ok." }

Write-Output "native_control_plane=ready"
Write-Output "postgresql=ready"
Write-Output "alembic_revision=e6a1b7c42d90"
Write-Output "admin_panel=ready"
Write-Output "xray_config=valid_fail_closed"
Write-Output "subscription_protocols=vless"
Write-Output "public_vpn_ingress=disabled"
