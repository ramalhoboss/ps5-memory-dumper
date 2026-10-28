# Builds one self-contained dist\PS5 Memory Dumper.exe: copy just that file to any Windows PC, no Python needed.
# Run from this folder:  powershell -ExecutionPolicy Bypass -File build_exe.ps1
# The icon and artwork come from "icone 2.png", Icon.png and Logo.jpg in this folder; replace them and rebuild to change them.
# What goes into the .exe is set in "PS5 Memory Dumper.spec".
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Invoke-Step([string]$name, [scriptblock]$command) {
    Write-Host "`n== $name" -ForegroundColor Yellow
    & $command
    if ($LASTEXITCODE -ne 0) { throw "$name failed (exit code $LASTEXITCODE)" }
}

Invoke-Step "Installing build tools" { python -m pip install --upgrade pyinstaller -r requirements.txt }
Invoke-Step "Making icon and artwork from icone 2.png / Icon.png / Logo.jpg" { python make_assets.py }
Invoke-Step "Building PS5 Memory Dumper.exe" { python -m PyInstaller --noconfirm --clean "PS5 Memory Dumper.spec" }
Write-Host "`nDone: dist\PS5 Memory Dumper.exe (dumps are saved in a 'dumps' folder next to the .exe)" -ForegroundColor Green
