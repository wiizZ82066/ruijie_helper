param(
    [string]$BundleDirectory = 'release\local-6.2.4\CampusAuthenticatorFlet',
    [string]$OutputDirectory = 'release\nsis-6.2.4',
    [string]$Compiler = ''
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
# This script wraps an existing bundle. It never rebuilds or changes the app.
$versionSource = Get-Content -LiteralPath 'utils\app_version.py' -Raw
$version = [regex]::Match($versionSource, '(?m)^VERSION\s*=\s*[''"]([0-9]+\.[0-9]+\.[0-9]+)[''"]').Groups[1].Value
if (-not $version) { throw 'Cannot read application version.' }
$bundle = (Resolve-Path -LiteralPath $BundleDirectory).Path
$main = Join-Path $bundle 'CampusAuthenticatorFlet.exe'
if (-not (Test-Path -LiteralPath $main -PathType Leaf)) { throw 'Main executable missing. Do not restore quarantined files to build an installer.' }
$mainHash = (Get-FileHash -LiteralPath $main -Algorithm SHA256 -ErrorAction Stop).Hash
$releaseRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'release'))
$output = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $OutputDirectory))
if (-not $output.StartsWith($releaseRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Output must be a subdirectory of release.' }
if (-not $Compiler) {
    $command = Get-Command makensis.exe -ErrorAction SilentlyContinue
    if ($command) { $Compiler = $command.Source }
    else { $Compiler = Join-Path $PSScriptRoot 'build\installer-tools\nsis\nsis-3.13\makensis.exe' }
}
if (-not (Test-Path -LiteralPath $Compiler -PathType Leaf)) { throw 'Install official NSIS 3 and pass -Compiler with its makensis.exe path.' }
$files = @(Get-ChildItem -LiteralPath $bundle -Recurse -File | Sort-Object FullName)
$entries = @(Get-Item -LiteralPath $bundle) + @(Get-ChildItem -LiteralPath $bundle -Recurse)
if ($entries | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) { throw 'Bundle must not contain reparse points.' }
if ($files | Where-Object { $_.Name -match '^(config\.json|settings\.json|SuConfig\.dat|userinfo\.dat)$|\.(log|dpapi|pcap|pcapng)$' }) { throw 'Private runtime data found in bundle.' }
function Escape-Nsis([string]$value) {
    if ($value -match '[\r\n"]') { throw 'Unsupported path in bundle.' }
    return $value.Replace('$', '$$')
}
$stage = Join-Path $PSScriptRoot ('build\nsis-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage, $output -Force | Out-Null
try {
    $copy = [Collections.Generic.List[string]]::new()
    $delete = [Collections.Generic.List[string]]::new()
    $directories = [Collections.Generic.HashSet[string]]::new()
    foreach ($file in $files) {
        $relative = $file.FullName.Substring($bundle.Length + 1)
        if ($relative -in @('Uninstall.exe', 'installation.log', 'unins000.exe', 'unins000.dat')) { throw 'Bundle contains installer-owned files.' }
        $parent = Split-Path $relative -Parent
        $copy.Add('SetOutPath "$INSTDIR' + $(if ($parent) { '\' + (Escape-Nsis $parent) }) + '"')
        $copy.Add('File "' + (Escape-Nsis $file.FullName) + '"')
        $copy.Add('IfErrors copyFailed')
        $delete.Add('Delete "$INSTDIR\' + (Escape-Nsis $relative) + '"')
        while ($parent) { $null = $directories.Add($parent); $parent = Split-Path $parent -Parent }
    }
    foreach ($directory in ($directories | Sort-Object Length -Descending)) { $delete.Add('RMDir "$INSTDIR\' + (Escape-Nsis $directory) + '"') }
    $payload = Join-Path $stage 'payload.nsh'
    $uninstall = Join-Path $stage 'uninstall.nsh'
    [IO.File]::WriteAllLines($payload, $copy, [Text.UTF8Encoding]::new($true))
    [IO.File]::WriteAllLines($uninstall, $delete, [Text.UTF8Encoding]::new($true))
    $setup = Join-Path $output "CampusAuthenticator-Setup-$version-nsis-win-x64.exe"
    & $Compiler /INPUTCHARSET UTF8 /V2 "/DAppVersion=$version" "/DOutputFile=$setup" "/DPayloadInclude=$payload" "/DUninstallInclude=$uninstall" (Join-Path $PSScriptRoot 'installer\CampusAuthenticator.nsi')
    if ($LASTEXITCODE -ne 0) { throw 'NSIS compilation failed.' }
    if ((Get-FileHash -LiteralPath $main -Algorithm SHA256).Hash -ne $mainHash) { throw 'Main executable changed during compilation.' }
    $hash = (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $(Split-Path $setup -Leaf)" | Set-Content -LiteralPath (Join-Path $output 'SHA256SUMS.txt') -Encoding ascii
    Write-Output "Created NSIS installer; application SHA256 unchanged: $mainHash"
} finally {
    $checkedStage = [IO.Path]::GetFullPath($stage)
    $buildRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'build')) + '\'
    if ($checkedStage.StartsWith($buildRoot, [StringComparison]::OrdinalIgnoreCase) -and (Split-Path $checkedStage -Leaf) -match '^nsis-[0-9a-f]{32}$') {
        Remove-Item -LiteralPath $checkedStage -Recurse -Force
    }
}
