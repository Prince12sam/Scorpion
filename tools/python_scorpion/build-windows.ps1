Param(
    [string]$Name = "scorpion",
    [string]$Entry = "runner.py"
)

# Build a single-file Windows binary via PyInstaller
Write-Host "Building $Name (Windows onefile)" -ForegroundColor Cyan

if (-not (Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
    Write-Host "PyInstaller not found. Installing into current environment..." -ForegroundColor Yellow
    pip install pyinstaller | Out-Null
}

Push-Location $PSScriptRoot
try {
    $entryPath = Join-Path $PSScriptRoot $Entry
    pyinstaller --noconfirm --onefile --name $Name $entryPath | Out-String | Write-Host
    Write-Host "Build complete. Binary at: $(Join-Path $PSScriptRoot 'dist' $Name).exe" -ForegroundColor Green
}
finally {
    Pop-Location
}
