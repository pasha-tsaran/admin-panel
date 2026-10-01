[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$runtimeRoot = Join-Path $projectRoot ".local"
$dataRoot = Join-Path $runtimeRoot "postgres-data"
$logRoot = Join-Path $runtimeRoot "logs"
$envFile = Join-Path $projectRoot ".env.native"
$postgresBin = "C:\Program Files\PostgreSQL\18\bin"
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$xray = Join-Path $runtimeRoot "xray-26.3.27\xray.exe"

if (-not (Test-Path -LiteralPath $envFile -PathType Leaf)) {
    throw "Run deploy/local/init-native.ps1 first."
}
foreach ($line in [IO.File]::ReadAllLines($envFile)) {
    if ($line -match "^([A-Z0-9_]+)=(.*)$") {
        [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], "Process")
    }
}
if (-not $env:KENAI_NATIVE_POSTGRES_PORT -or -not $env:KENAI_NATIVE_POSTGRES_PASSWORD) {
    throw "Native environment file is incomplete."
}

New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
$env:PGPASSWORD = $env:KENAI_NATIVE_POSTGRES_PASSWORD
& (Join-Path $postgresBin "pg_ctl.exe") status -D $dataRoot *> $null
if ($LASTEXITCODE -ne 0) {
    & (Join-Path $postgresBin "pg_ctl.exe") start -D $dataRoot -l (Join-Path $logRoot "postgres.log") -w
    if ($LASTEXITCODE -ne 0) { throw "PostgreSQL failed to start." }
}

& (Join-Path $postgresBin "psql.exe") --no-password -h 127.0.0.1 -p $env:KENAI_NATIVE_POSTGRES_PORT -U kenai -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='kenai'" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "PostgreSQL connection check failed." }
$exists = [string](& (Join-Path $postgresBin "psql.exe") --no-password -h 127.0.0.1 -p $env:KENAI_NATIVE_POSTGRES_PORT -U kenai -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='kenai'")
if ($exists -ne "1") {
    & (Join-Path $postgresBin "createdb.exe") --no-password -h 127.0.0.1 -p $env:KENAI_NATIVE_POSTGRES_PORT -U kenai kenai
    if ($LASTEXITCODE -ne 0) { throw "Could not create the Kenai database." }
}

Set-Location $projectRoot
& $python -m alembic -c alembic.ini upgrade head
if ($LASTEXITCODE -ne 0) { throw "Alembic migration failed." }

$xrayPidFile = Join-Path $runtimeRoot "xray.pid"
if (-not (Test-Path -LiteralPath $xrayPidFile)) {
    $xrayProcess = Start-Process -FilePath $xray -ArgumentList @("run", "-config", "deploy/local/xray-control-plane.json") -WorkingDirectory $projectRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logRoot "xray.stdout.log") -RedirectStandardError (Join-Path $logRoot "xray.stderr.log") -PassThru
    [IO.File]::WriteAllText($xrayPidFile, $xrayProcess.Id.ToString(), [Text.Encoding]::ASCII)
}

$webPidFile = Join-Path $runtimeRoot "web.pid"
if (-not (Test-Path -LiteralPath $webPidFile)) {
    $webProcess = Start-Process -FilePath $python -ArgumentList @("-m", "uvicorn", "kenai_vpn_admin.main:app", "--host", "127.0.0.1", "--port", "8000") -WorkingDirectory $projectRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logRoot "web.stdout.log") -RedirectStandardError (Join-Path $logRoot "web.stderr.log") -PassThru
    [IO.File]::WriteAllText($webPidFile, $webProcess.Id.ToString(), [Text.Encoding]::ASCII)
}

$deadline = [DateTime]::UtcNow.AddSeconds(30)
do {
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/healthz" -Method Get -TimeoutSec 2
        if ($health.status -eq "ok") { break }
    }
    catch {
        Start-Sleep -Milliseconds 500
    }
} while ([DateTime]::UtcNow -lt $deadline)
if (-not $health -or $health.status -ne "ok") {
    throw "Kenai web panel did not become healthy; inspect .local/logs/web.stderr.log."
}

Write-Output "native_control_plane=ready"
Write-Output "panel=http://127.0.0.1:8000"
Write-Output "vpn_backend=mock"
Write-Output "public_vpn_ingress=disabled"
