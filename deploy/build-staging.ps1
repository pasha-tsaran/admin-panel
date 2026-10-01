[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "artifacts")
)

$ErrorActionPreference = "Stop"
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
$workspacePrefix = $projectRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar

if (-not $outputRoot.StartsWith($workspacePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Output directory must be inside the project workspace"
}

$ruff = Join-Path $projectRoot ".venv\Scripts\ruff.exe"
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
foreach ($tool in @($ruff, $python)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
        throw "Required local QA tool is unavailable: $tool"
    }
}

Push-Location $projectRoot
try {
    & $ruff format --check src tests migrations
    if ($LASTEXITCODE -ne 0) { throw "ruff format check failed" }
    & $ruff check src tests migrations
    if ($LASTEXITCODE -ne 0) { throw "ruff check failed" }
    & $python -m mypy src
    if ($LASTEXITCODE -ne 0) { throw "mypy failed" }

    $testRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot (".test-tmp-staging-" + [guid]::NewGuid().ToString("N"))))
    if (-not $testRoot.StartsWith($workspacePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe test path"
    }
    try {
        & $python -m pytest -p no:cacheprovider --basetemp $testRoot
        if ($LASTEXITCODE -ne 0) { throw "pytest failed" }
    }
    finally {
        if (Test-Path -LiteralPath $testRoot) {
            $resolvedTestRoot = (Resolve-Path -LiteralPath $testRoot).Path
            if (-not $resolvedTestRoot.StartsWith($workspacePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Unsafe test cleanup path"
            }
            Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
        }
    }

    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $stagingRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot ("deploy\.staging-build-" + [guid]::NewGuid().ToString("N"))))
    if (-not $stagingRoot.StartsWith($workspacePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe staging path"
    }
    New-Item -ItemType Directory -Path $stagingRoot | Out-Null
    try {
        $topLevelFiles = @(
            ".env.example", ".gitattributes", ".gitignore", "AGENTS.md",
            "CHANGES.md", "CONTRIBUTING.md", "README.md", "SECURITY.md", "alembic.ini", "pyproject.toml"
        )
        foreach ($relative in $topLevelFiles) {
            Copy-Item -LiteralPath (Join-Path $projectRoot $relative) -Destination $stagingRoot
        }
        foreach ($directory in @("src", "tests", "migrations", "docs")) {
            Copy-Item -LiteralPath (Join-Path $projectRoot $directory) -Destination $stagingRoot -Recurse
        }
        New-Item -ItemType Directory -Path (Join-Path $stagingRoot "deploy") | Out-Null
        foreach ($directory in @("install", "nginx", "preflight", "systemd")) {
            Copy-Item -LiteralPath (Join-Path $projectRoot "deploy\$directory") -Destination (Join-Path $stagingRoot "deploy") -Recurse
        }
        Copy-Item -LiteralPath (Join-Path $projectRoot "deploy\helper.env.example") -Destination (Join-Path $stagingRoot "deploy")
        Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $stagingRoot "deploy")

        Get-ChildItem -LiteralPath $stagingRoot -Recurse -Force -Directory |
            Where-Object { $_.Name -in @('__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache') } |
            Sort-Object { $_.FullName.Length } -Descending |
            Remove-Item -Recurse -Force
        Get-ChildItem -LiteralPath $stagingRoot -Recurse -Force -File |
            Where-Object { $_.Extension -in @('.pyc', '.pyo') } |
            Remove-Item -Force

        $forbidden = Get-ChildItem -LiteralPath $stagingRoot -Recurse -Force -File | Where-Object {
            $_.Name -match '^(\.env|backup\.key)$' -or
            $_.Extension -in @('.db', '.sqlite', '.sqlite3', '.key', '.pem', '.p12', '.pfx', '.uri', '.kvbackup', '.log', '.pyc', '.pyo') -or
            $_.FullName -match '[\\/](incoming|artifacts|runtime|logs|provisioning|client-configs|private-keys)[\\/]'
        }
        if ($forbidden) { throw "Forbidden files reached staging" }

        $manifest = @(
            "Kenai VPN Admin staging build", "created_utc=$timestamp",
            "ruff_format=PASS", "ruff_check=PASS", "mypy_strict=PASS", "pytest=PASS",
            "backup_web_integration=DEFERRED_TO_FINAL_PROJECT_GATE", "source_secrets_included=NO"
        )
        Set-Content -LiteralPath (Join-Path $stagingRoot "BUILD-MANIFEST.txt") -Value $manifest -Encoding UTF8

        New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
        $archive = Join-Path $outputRoot "kenai-vpn-staging-$timestamp.tar.gz"
        tar.exe -czf $archive -C $stagingRoot .
        if ($LASTEXITCODE -ne 0) { throw "tar archive creation failed" }
        tar.exe -tzf $archive | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "tar archive verification failed" }

        $digest = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        $memberCount = @(tar.exe -tzf $archive).Count
        Write-Output "archive=$archive"
        Write-Output "sha256=$digest"
        Write-Output "members=$memberCount"
        Write-Output "quality=PASS"
        Write-Output "secret_policy=PASS"
    }
    finally {
        if (Test-Path -LiteralPath $stagingRoot) {
            $resolvedStagingRoot = (Resolve-Path -LiteralPath $stagingRoot).Path
            if (-not $resolvedStagingRoot.StartsWith($workspacePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Unsafe staging cleanup path"
            }
            Remove-Item -LiteralPath $resolvedStagingRoot -Recurse -Force
        }
    }
}
finally {
    Pop-Location
}
