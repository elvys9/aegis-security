param([ValidateSet('nsis','msi')][string]$Bundle = 'nsis')
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    if ($Bundle -eq 'msi') {
        Write-Warning 'MSI is experimental: NSIS Explorer integration and protected ProgramData initialization do not run in WiX. Do not distribute as equivalent.'
    }
    & npm.cmd run tauri -- build --bundles $Bundle
    if ($LASTEXITCODE -ne 0) { throw "Tauri build failed ($LASTEXITCODE)" }
    Write-Host 'Unsigned prerelease artifacts: src-tauri/target/release/bundle. Signing and clean-machine validation remain mandatory release gates.'
} finally { Pop-Location }
