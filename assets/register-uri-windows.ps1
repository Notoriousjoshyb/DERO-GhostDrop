# Register ghostdrop:// URI handling on Windows (per-user, no admin needed).
$ErrorActionPreference = "Stop"
$exe = (Get-Command ghostdrop -ErrorAction SilentlyContinue).Source
if (-not $exe) { $exe = Join-Path (Get-Location) "ghostdrop.exe" }
$key = "HKCU:\Software\Classes\ghostdrop"
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name "(Default)" -Value "URL:Ghostdrop"
Set-ItemProperty -Path $key -Name "URL Protocol" -Value ""
New-Item -Path "$key\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path "$key\shell\open\command" -Name "(Default)" -Value "`"$exe`" --open-url `"%1`""
Write-Host "Registered ghostdrop:// -> $exe"
