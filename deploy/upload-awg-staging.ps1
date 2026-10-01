$ErrorActionPreference = "Stop"

$archive = Join-Path $PSScriptRoot "artifacts\kenai-vpn-staging-20260901T213709Z.tar.gz"
$expectedDigest = "82d61109c705e828f54f98d03d3f30acfcc0b6d3104771066f06e394f47e7698"

if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
    throw "Staging archive is missing: $archive"
}

$actualDigest = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualDigest -ne $expectedDigest) {
    throw "Staging archive digest mismatch"
}

Write-Host "Archive digest verified. Uploading to codexuser@88.218.94.3:/home/codexuser/"
Write-Host "Enter the VPS password in this window if OpenSSH requests it."
& scp.exe -o StrictHostKeyChecking=yes -- $archive "codexuser@88.218.94.3:/home/codexuser/"
if ($LASTEXITCODE -ne 0) {
    throw "SCP upload failed with exit code $LASTEXITCODE"
}

Write-Host "Upload completed. Production was not installed or restarted."
Read-Host "Press Enter to close"
