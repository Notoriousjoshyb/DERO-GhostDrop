# Ghostdrop test (Windows). Runs the owned integration + acceptance suite.
# Usage: powershell -NoProfile -File scripts/test.ps1   ($env:GHOSTDROP_BIG=1 for 1 GiB)
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

Write-Host '==> go vet (owned tests only)'
go vet ./tests/

Write-Host "==> integration + acceptance (default 64 MiB; GHOSTDROP_BIG=1 -> 1 GiB)"
go test ./tests/ -run 'Integration|Acceptance' -count=1 -v

Write-Host 'OK: tests passed.'
