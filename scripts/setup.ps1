# Ghostdrop setup (Windows 11). Detects Go >= 1.24 and missing deps.
$ErrorActionPreference = 'Stop'
$MinGo = [Version]'1.24.0'
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

Write-Host '==> Ghostdrop setup'
Write-Host ("    OS: " + [System.Environment]::OSVersion.VersionString)

$go = Get-Command go -ErrorAction SilentlyContinue
if (-not $go) {
  Write-Host "ERROR: 'go' not found on PATH."
  Write-Host '  Install Go >= 1.24 from https://go.dev/dl/ or: winget install GoLang.Go'
  exit 1
}
$verOut = (go version)  # e.g. "go version go1.24.3 windows/amd64"
if ($verOut -match 'go(\d+\.\d+(?:\.\d+)?)') {
  $v = $Matches[1]; if ($v.Split('.').Count -eq 2) { $v += '.0' }
  $found = [Version]$v
  Write-Host "    go: $found ($($go.Source))"
  if ($found -lt $MinGo) {
    Write-Host "ERROR: Go >= $MinGo required (found $found)."
    exit 1
  }
} else {
  Write-Host "WARNING: could not parse Go version from: $verOut"
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  Write-Host "WARNING: 'git' missing — winget install Git.Git"
}

Write-Host '==> go mod download'
go mod download
Write-Host '==> go mod tidy (allowed adds: uuid, go-qrcode, x/crypto, modernc.org/sqlite)'
go mod tidy
Write-Host 'OK: setup complete. Next: powershell -NoProfile -File scripts/build.ps1'
