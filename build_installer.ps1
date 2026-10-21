param(
    [string]$OutputDirectory = 'release\v6.2.3',
    [string]$Version = '6.2.3',
    [string]$Compiler = '',
    [string]$ChineseMessages = '',
    [switch]$SkipAppBuild
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if ($Version -notmatch '^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$') { throw 'Invalid version.' }
$sourceVersion = (& python -c 'from utils.app_version import VERSION; print(VERSION)').Trim()
if ($LASTEXITCODE -ne 0 -or $sourceVersion -ne $Version) { throw 'Installer version must match utils/app_version.py.' }
$releaseRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'release'))
$outputRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $OutputDirectory))
if (-not $outputRoot.StartsWith($releaseRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Output must be a subdirectory of release.' }
if (-not $Compiler) {
    $command = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($command) { $Compiler = $command.Source }
    else { $Compiler = Join-Path $PSScriptRoot 'build\installer-tools\inno\ISCC.exe' }
}
if (-not (Test-Path -LiteralPath $Compiler -PathType Leaf)) { throw 'Install Inno Setup 6.7+ and pass -Compiler with its ISCC.exe path.' }
if (-not $ChineseMessages) { $ChineseMessages = Join-Path (Split-Path $Compiler) 'Languages\ChineseSimplified.isl' }
if (-not (Test-Path -LiteralPath $ChineseMessages -PathType Leaf)) { throw 'Pass -ChineseMessages with the official Inno Setup ChineseSimplified.isl translation.' }
if (-not $SkipAppBuild) {
    & (Join-Path $PSScriptRoot 'build_flet.ps1') -OutputDirectory $OutputDirectory
    if ($LASTEXITCODE -ne 0) { throw 'App build failed.' }
}
$bundle = Join-Path $outputRoot 'CampusAuthenticatorFlet'
if (-not (Test-Path -LiteralPath (Join-Path $bundle 'CampusAuthenticatorFlet.exe'))) { throw 'App bundle missing.' }
& $Compiler "/DBundleDir=$bundle" "/DReleaseDir=$outputRoot" "/DAppVersion=$Version" "/DChineseMessages=$ChineseMessages" (Join-Path $PSScriptRoot 'installer\CampusAuthenticator.iss')
if ($LASTEXITCODE -ne 0) { throw 'Installer compilation failed.' }
$setup = Join-Path $outputRoot "CampusAuthenticator-Setup-$Version-win-x64.exe"
$hash = (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $(Split-Path $setup -Leaf)" | Set-Content -LiteralPath (Join-Path $outputRoot 'SHA256SUMS.txt') -Encoding ascii
Write-Output "Created installer: $setup"
