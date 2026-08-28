$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$ToolRoot = Split-Path -Parent $Root
Set-Location $ToolRoot

Write-Host "==> npm ci"
npm ci

Write-Host "==> build frontend"
npm run build:local

Write-Host "==> tauri build"
npm run tauri:build

$ReleaseDir = Join-Path $ToolRoot "src-tauri\target\release"
$DistDir = Join-Path $ToolRoot "dist\CsvVtScanner"
$DataDir = Join-Path $DistDir "data"

New-Item -ItemType Directory -Force -Path $DistDir, $DataDir | Out-Null

$BuiltExe = Get-ChildItem -Path $ReleaseDir -Filter "*.exe" |
  Where-Object { $_.Name -notlike "*setup*" -and $_.Name -notlike "*installer*" } |
  Select-Object -First 1

if (-not $BuiltExe) {
  throw "Eseguibile non trovato in $ReleaseDir"
}

Copy-Item $BuiltExe.FullName (Join-Path $DistDir "csv-vt-scanner.exe") -Force
Write-Host "Portable: $DistDir"
