Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$Python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $Python) {
    $Python = (Get-Command py -ErrorAction SilentlyContinue).Source
}
if (-not $Python) {
    throw "Python was not found. Install Python 3.10+ or use a machine that already has Python to build the EXE."
}

if (Test-Path ".venv-build") {
    Remove-Item -LiteralPath ".venv-build" -Recurse -Force
}
& $Python -m venv .venv-build
$VenvPython = Join-Path $Root ".venv-build\Scripts\python.exe"
& $VenvPython -m pip install --upgrade pip
& $VenvPython -m pip install pyinstaller

if (Test-Path "build") { Remove-Item -LiteralPath "build" -Recurse -Force }
if (Test-Path "dist") { Remove-Item -LiteralPath "dist" -Recurse -Force }

& $VenvPython -m PyInstaller `
    --clean `
    --noconfirm `
    --name SecurityAudit `
    --onefile `
    --console `
    --uac-admin `
    --paths "$Root\src" `
    "$Root\src\win_security_audit\__main__.py"

$ReleaseDir = Join-Path $Root "release\SecurityAuditTool"
if (Test-Path $ReleaseDir) { Remove-Item -LiteralPath $ReleaseDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $ReleaseDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $ReleaseDir "tools\sysinternals") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $ReleaseDir "src") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $ReleaseDir "tests") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $ReleaseDir ".github") | Out-Null

Copy-Item -LiteralPath "$Root\dist\SecurityAudit.exe" -Destination $ReleaseDir
Copy-Item -LiteralPath "$Root\run_audit.cmd" -Destination $ReleaseDir
Copy-Item -LiteralPath "$Root\build.ps1" -Destination $ReleaseDir
Copy-Item -LiteralPath "$Root\README.md" -Destination $ReleaseDir
Copy-Item -LiteralPath "$Root\LICENSE" -Destination $ReleaseDir
Copy-Item -LiteralPath "$Root\pyproject.toml" -Destination $ReleaseDir
Copy-Item -LiteralPath "$Root\.gitignore" -Destination $ReleaseDir
Copy-Item -Path "$Root\src\*" -Destination (Join-Path $ReleaseDir "src") -Recurse
Copy-Item -Path "$Root\tests\*" -Destination (Join-Path $ReleaseDir "tests") -Recurse
Copy-Item -Path "$Root\.github\*" -Destination (Join-Path $ReleaseDir ".github") -Recurse
Copy-Item -LiteralPath "$Root\tools\sysinternals\README.md" -Destination (Join-Path $ReleaseDir "tools\sysinternals") -ErrorAction SilentlyContinue

Get-ChildItem -LiteralPath $ReleaseDir -Directory -Recurse -Filter "__pycache__" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force
Get-ChildItem -LiteralPath $ReleaseDir -File -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in ".pyc", ".pyo" } |
    Remove-Item -Force

$Zip = Join-Path $Root "release\SecurityAuditTool.zip"
if (Test-Path $Zip) { Remove-Item -LiteralPath $Zip -Force }
Compress-Archive -Path "$ReleaseDir\*" -DestinationPath $Zip -Force

Write-Host "Built EXE: $Root\dist\SecurityAudit.exe"
Write-Host "Built ZIP: $Zip"
