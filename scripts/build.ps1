# Ghostdrop build (Windows). Builds .exe binaries into bin/.
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot
New-Item -ItemType Directory -Force -Path bin | Out-Null

Write-Host '==> building ghostdrop'
go build -trimpath -o bin/ghostdrop.exe ./cmd/ghostdrop
Write-Host '==> building ghostdrop-cli'
go build -trimpath -o bin/ghostdrop-cli.exe ./cmd/ghostdrop-cli
Write-Host '==> building ghostdrop-relay'
go build -trimpath -o bin/ghostdrop-relay.exe ./cmd/ghostdrop-relay

Get-ChildItem bin/
Write-Host 'OK: build complete.'
