param([switch]$SingleFile)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$env:PYINSTALLER_CONFIG_DIR = Join-Path $PSScriptRoot 'build\pyinstaller-cache'
$iconPath = Join-Path $PSScriptRoot 'icon\app.ico'
$pythonExecutable = (Get-Command python -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$originalBuildPath = $env:Path
$layout = if ($SingleFile) { '--onefile' } else { '--onedir' }
& $pythonExecutable (Join-Path $PSScriptRoot 'tools\audit_release.py')
if ($LASTEXITCODE -ne 0) { throw 'Source release audit failed; build stopped.' }
try {
    # Qt imports the Windows ICU ABI. Prefer System32 over unrelated tools on
    # PATH (such as Poppler, whose icuuc.dll exports version-suffixed symbols).
    $env:Path = "$(Join-Path $env:SystemRoot 'System32');$env:SystemRoot;$originalBuildPath"
    # Directory builds avoid extracting the Qt runtime on every launch. The
    # manifest asks for elevation before Python starts, avoiding a second load.
    & $pythonExecutable -m PyInstaller --clean --noconfirm $layout --windowed --uac-admin --name CampusAuthenticator --icon $iconPath --add-data "$iconPath;icon" --collect-binaries Crypto --exclude-module Crypto.SelfTest --distpath release --workpath build/authenticator --specpath build campus_authenticator.py
    if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
} finally {
    $env:Path = $originalBuildPath
}
if ($SingleFile) {
    Write-Output "Created: $(Join-Path $PSScriptRoot 'release\CampusAuthenticator.exe')"
} else {
    $bundle = Join-Path $PSScriptRoot 'release\CampusAuthenticator'
    $guide = Join-Path $PSScriptRoot 'docs\user-guide.txt'
    if (Test-Path -LiteralPath $guide) { Copy-Item -LiteralPath $guide -Destination (Join-Path $bundle 'user-guide.txt') -Force }
    $archive = Join-Path $PSScriptRoot 'release\CampusAuthenticator-win-x64.zip'
    Compress-Archive -LiteralPath $bundle -DestinationPath $archive -Force
    Write-Output "Created: $(Join-Path $bundle 'CampusAuthenticator.exe')"
    Write-Output "Release archive: $archive"
}
