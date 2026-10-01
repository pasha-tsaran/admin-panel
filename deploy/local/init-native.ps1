[CmdletBinding()]
param(
    [int]$PostgresPort = 55432
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$runtimeRoot = Join-Path $projectRoot ".local"
$dataRoot = Join-Path $runtimeRoot "postgres-data"
$logRoot = Join-Path $runtimeRoot "logs"
$envFile = Join-Path $projectRoot ".env.native"
$postgresBin = "C:\Program Files\PostgreSQL\18\bin"

if (-not (Test-Path -LiteralPath (Join-Path $postgresBin "initdb.exe") -PathType Leaf)) {
    throw "PostgreSQL 18 binaries were not found at $postgresBin."
}
if ((Test-Path -LiteralPath $envFile) -or (Test-Path -LiteralPath $dataRoot)) {
    throw "Native environment already exists or is partial; existing data was not changed."
}
if ($PostgresPort -lt 1024 -or $PostgresPort -gt 65535) {
    throw "PostgreSQL port must be between 1024 and 65535."
}

function New-Base64UrlSecret([int]$ByteCount) {
    $bytes = [byte[]]::new($ByteCount)
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) }
    finally { $generator.Dispose() }
    return [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

New-Item -ItemType Directory -Path $runtimeRoot,$logRoot -Force | Out-Null
$postgresPassword = New-Base64UrlSecret 36
$passwordFile = Join-Path $runtimeRoot "postgres-password.tmp"
$encoding = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText($passwordFile, $postgresPassword + [Environment]::NewLine, $encoding)
try {
    $passwordArgument = "--pwfile=$passwordFile"
    & (Join-Path $postgresBin "initdb.exe") -D $dataRoot -U kenai $passwordArgument --auth-local=scram-sha-256 --auth-host=scram-sha-256 --encoding=UTF8
    if ($LASTEXITCODE -ne 0) { throw "initdb failed." }
}
finally {
    Remove-Item -LiteralPath $passwordFile -Force -ErrorAction SilentlyContinue
}

Add-Content -LiteralPath (Join-Path $dataRoot "postgresql.conf") -Encoding UTF8 -Value @(
    "listen_addresses = '127.0.0.1'"
    "port = $PostgresPort"
    "timezone = 'UTC'"
    "log_timezone = 'UTC'"
)

$databaseUrl = "postgresql+psycopg://kenai:$postgresPassword@127.0.0.1:$PostgresPort/kenai"
$lines = @(
    "KENAI_ENV=development"
    "KENAI_DATABASE_URL=$databaseUrl"
    "KENAI_SECRET_KEY=$(New-Base64UrlSecret 48)"
    "KENAI_ENCRYPTION_KEY=$(New-Base64UrlSecret 32)="
    "KENAI_VPN_BACKEND=mock"
    "KENAI_SUBSCRIPTION_PROTOCOLS=vless"
    "KENAI_COOKIE_SECURE=false"
    "KENAI_HOST=127.0.0.1"
    "KENAI_PORT=8000"
    "KENAI_NATIVE_POSTGRES_PASSWORD=$postgresPassword"
    "KENAI_NATIVE_POSTGRES_PORT=$PostgresPort"
)
[IO.File]::WriteAllLines($envFile, $lines, $encoding)

& (Join-Path $PSScriptRoot "install-native-xray.ps1")
if ($LASTEXITCODE -ne 0) { throw "Native Xray installation failed." }

Write-Output "native_environment=initialized"
Write-Output "secret_values_printed=0"
Write-Output "next=deploy/local/start-native.ps1"
