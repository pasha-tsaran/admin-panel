[CmdletBinding()]
param(
    [string]$EnvFile = ".env.local"
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $projectRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker Desktop is not installed or docker.exe is not in PATH."
}
if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
    throw "Missing $EnvFile. Run deploy/local/init-local.ps1 first."
}

docker compose --env-file $EnvFile config --quiet
if ($LASTEXITCODE -ne 0) { throw "docker compose configuration is invalid" }

docker compose --env-file $EnvFile ps
if ($LASTEXITCODE -ne 0) { throw "docker compose stack is unavailable" }

docker compose --env-file $EnvFile exec -T xray xray run -test -config /etc/xray/config.json
if ($LASTEXITCODE -ne 0) { throw "Xray rejected the mounted configuration" }

$health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/healthz" -Method Get -TimeoutSec 5
if ($health.status -ne "ok") { throw "Kenai health endpoint did not return ok" }

docker compose --env-file $EnvFile run --rm admin alembic -c alembic.ini current
if ($LASTEXITCODE -ne 0) { throw "Alembic could not read the PostgreSQL revision" }

Write-Output "local_control_plane=ready"
Write-Output "postgresql=ready"
Write-Output "admin_panel=ready"
Write-Output "xray_config=valid"
