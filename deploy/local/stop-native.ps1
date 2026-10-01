[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$runtimeRoot = Join-Path $projectRoot ".local"
$dataRoot = Join-Path $runtimeRoot "postgres-data"
$envFile = Join-Path $projectRoot ".env.native"
$postgresBin = "C:\Program Files\PostgreSQL\18\bin"

function Stop-OwnedProcess([string]$PidFile, [string]$ExpectedName) {
    if (-not (Test-Path -LiteralPath $PidFile -PathType Leaf)) { return }
    $processId = [int]([IO.File]::ReadAllText($PidFile).Trim())
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($process -and $process.ProcessName -ne $ExpectedName) {
        throw "Refusing to stop unexpected process $($process.ProcessName) from $PidFile."
    }
    if ($process) { Stop-Process -Id $processId -Force }
    Remove-Item -LiteralPath $PidFile -Force
}

Stop-OwnedProcess (Join-Path $runtimeRoot "web.pid") "python"
Stop-OwnedProcess (Join-Path $runtimeRoot "xray.pid") "xray"

if (Test-Path -LiteralPath $envFile -PathType Leaf) {
    foreach ($line in [IO.File]::ReadAllLines($envFile)) {
        if ($line -match "^KENAI_NATIVE_POSTGRES_PASSWORD=(.*)$") { $env:PGPASSWORD = $Matches[1] }
    }
}
& (Join-Path $postgresBin "pg_ctl.exe") status -D $dataRoot *> $null
if ($LASTEXITCODE -eq 0) {
    & (Join-Path $postgresBin "pg_ctl.exe") stop -D $dataRoot -m fast -w
}

Write-Output "native_control_plane=stopped"
