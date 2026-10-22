param(
    [switch]$PrepareRuntimeOnly,
    [string]$OutputDirectory = 'release',
    [string]$PythonExecutable = ''
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { throw 'OutputDirectory must not be empty.' }
$releaseRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'release'))
$outputRoot = if ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
    [System.IO.Path]::GetFullPath($OutputDirectory)
} else {
    [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot $OutputDirectory))
}
$releasePrefix = $releaseRoot.TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar
if (-not ($outputRoot.Equals($releaseRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
          $outputRoot.StartsWith($releasePrefix, [System.StringComparison]::OrdinalIgnoreCase))) {
    throw 'OutputDirectory must resolve inside this project release directory.'
}
$bundle = Join-Path $outputRoot 'CampusAuthenticatorFlet'
# PyInstaller replaces this bundle. Reject links before any recursive operation.
$inspectionPath = $bundle
while ($inspectionPath -and $inspectionPath.StartsWith($releaseRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    if (Test-Path -LiteralPath $inspectionPath) {
        $entry = Get-Item -LiteralPath $inspectionPath -Force
        if ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw 'Release output paths must not contain symbolic links or junctions.'
        }
    }
    if ($inspectionPath.Equals($releaseRoot, [System.StringComparison]::OrdinalIgnoreCase)) { break }
    $inspectionPath = Split-Path -Parent $inspectionPath
}
if (-not $PythonExecutable) {
    $PythonExecutable = (Get-Command python -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
}
$PythonExecutable = (Resolve-Path -LiteralPath $PythonExecutable -ErrorAction Stop).Path
$env:PYINSTALLER_CONFIG_DIR = Join-Path $PSScriptRoot 'build\pyinstaller-flet-cache'
& $pythonExecutable -c 'from pathlib import Path; from utils.flet_runtime import prepare_runtime; print(prepare_runtime(Path.cwd()))'
if ($LASTEXITCODE -ne 0) { throw 'Pinned desktop runtime preparation failed.' }
if ($PrepareRuntimeOnly) { exit 0 }
& $pythonExecutable (Join-Path $PSScriptRoot 'tools\audit_release.py')
if ($LASTEXITCODE -ne 0) { throw 'Source release audit failed; build stopped.' }
& $pythonExecutable -c 'from utils.flet_runtime import _check_versions; _check_versions()'
if ($LASTEXITCODE -ne 0) { throw 'Install requirements-flet.txt before building.' }
$hookDirectory = Join-Path $PSScriptRoot 'build\flet-hooks'
New-Item -ItemType Directory -Path $hookDirectory -Force | Out-Null
# Override Flet CLI's default hook, which may use/download a per-user runtime.
@'
from PyInstaller.utils.hooks import collect_data_files
datas = collect_data_files("flet.controls.material", includes=["icons.json"])
datas += collect_data_files("flet.controls.cupertino", includes=["cupertino_icons.json"])
'@ | Set-Content -LiteralPath (Join-Path $hookDirectory 'hook-flet.py') -Encoding ASCII
$iconPath = Join-Path $PSScriptRoot 'icon\app.ico'
$runtimePath = Join-Path $PSScriptRoot 'build\flet-runtime'
$originalBuildPath = $env:Path
# Flet exposes optional image-array and notebook helpers that PyInstaller's
# static analysis otherwise follows into scientific, notebook and Qt stacks.
# This desktop UI does not use these features.
$optionalModules = @('numpy', 'matplotlib', 'IPython', 'ipykernel', 'jupyter_client', 'jupyter_core', 'nbformat', 'nbclient', 'black', 'pytest', '_pytest', 'tkinter', '_tkinter', 'PySide2', 'shiboken6', 'shiboken2', 'pythonnet', 'clr', 'clr_loader')
$optionalExcludes = @()
foreach ($module in $optionalModules) { $optionalExcludes += @('--exclude-module', $module) }
try {
    $env:Path = "$(Join-Path $env:SystemRoot 'System32');$env:SystemRoot;$originalBuildPath"
    & $pythonExecutable -m PyInstaller --clean --noconfirm --noupx --onedir --windowed --uac-admin --name CampusAuthenticatorFlet --icon $iconPath --add-data "$iconPath;icon" --additional-hooks-dir $hookDirectory --hidden-import flet_desktop --hidden-import pystray._win32 --collect-binaries Crypto --exclude-module Crypto.SelfTest --exclude-module PySide6 --exclude-module PyQt6 --exclude-module PyQt5 --exclude-module flet_web --exclude-module flet_cli --exclude-module fastapi --exclude-module uvicorn @optionalExcludes --distpath $outputRoot --workpath build/authenticator-flet --specpath build campus_flet.py
    if ($LASTEXITCODE -ne 0) { throw 'Flet build failed.' }
} finally {
    $env:Path = $originalBuildPath
}
# Copy the standalone Flutter runtime after analysis. Feeding its executable
# and DLLs into PyInstaller creates a second flattened set of dependency DLLs.
$runtimeDestination = Join-Path $bundle '_internal\flet_runtime'
New-Item -ItemType Directory -Path $runtimeDestination -Force | Out-Null
Get-ChildItem -LiteralPath $runtimePath | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $runtimeDestination -Recurse -Force
}
& $pythonExecutable -c 'import sys; from pathlib import Path; from utils.flet_runtime import validate_runtime; validate_runtime(Path(sys.argv[1]))' $runtimeDestination
if ($LASTEXITCODE -ne 0) { throw 'Packaged runtime is missing or was modified; archive creation stopped.' }
$guide = Join-Path $PSScriptRoot 'docs\flet-user-guide.txt'
if (-not (Test-Path -LiteralPath $guide)) { throw 'Flet user guide is missing; archive creation stopped.' }
Copy-Item -LiteralPath $guide -Destination (Join-Path $bundle 'user-guide.txt') -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'docs\driver-installation.html') -Destination $bundle -Force
$archive = Join-Path $outputRoot 'CampusAuthenticatorFlet-win-x64.zip'
Compress-Archive -LiteralPath $bundle -DestinationPath $archive -Force
Write-Output "Created: $(Join-Path $bundle 'CampusAuthenticatorFlet.exe')"
Write-Output "Release archive: $archive"
