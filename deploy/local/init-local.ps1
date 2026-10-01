[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$target = Join-Path $projectRoot '.env.local'
if (Test-Path -LiteralPath $target) {
    throw '.env.local already exists; it was not changed.'
}

function New-Base64UrlSecret([int] $byteCount) {
    $bytes = [byte[]]::new($byteCount)
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) }
    finally { $generator.Dispose() }
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

$lines = @(
    'KENAI_POSTGRES_PASSWORD=' + (New-Base64UrlSecret 36)
    'KENAI_SECRET_KEY=' + (New-Base64UrlSecret 48)
    'KENAI_ENCRYPTION_KEY=' + (New-Base64UrlSecret 32) + '='
)
$encoding = [Text.UTF8Encoding]::new($false)
$stream = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $writer = [IO.StreamWriter]::new($stream, $encoding)
    try {
        foreach ($line in $lines) { $writer.WriteLine($line) }
        $writer.Flush()
    }
    finally {
        $writer.Dispose()
    }
}
finally {
    $stream.Dispose()
}

Write-Output 'local_environment_created=yes'
Write-Output 'secret_values_printed=0'
