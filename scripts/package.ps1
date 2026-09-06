# Ghostdrop packaging (Windows). Produces zip from bin/ + notes for installers.
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$Version = if ($env:GHOSTDROP_VERSION) { $env:GHOSTDROP_VERSION } else { '1.0.0' }
New-Item -ItemType Directory -Force -Path dist | Out-Null

if (-not (Test-Path bin) -or @(Get-ChildItem bin -ErrorAction SilentlyContinue).Count -eq 0) {
  Write-Host 'bin/ is empty -- building first.'
  powershell -NoProfile -File scripts/build.ps1
}

Write-Host "==> packing ghostdrop-$Version-win64.zip"
Compress-Archive -Path bin/*.exe -DestinationPath "dist/ghostdrop-$Version-win64.zip" -Force
Get-ChildItem dist/

Write-Host @'
Native package notes:
  .exe installer: wrap dist/ghostdrop-<ver>-win64.zip with Inno Setup
      (installer script outline in packaging.yml).
  .dmg (macOS, build on Mac): create-dmg --volname Ghostdrop bin/ghostdrop*.
  .deb/.rpm/AppImage/PKGBUILD: build on Linux via bash scripts/package.sh;
      layouts and spec outlines live in packaging.yml.
'@
Write-Host 'OK: packaging complete.'
