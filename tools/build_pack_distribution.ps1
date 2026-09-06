[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$SkipDependencyInstall,
    [switch]$NoArchive
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$distRoot = Join-Path $repoRoot 'dist'
$packageName = 'ampr-pack-tools-windows-x64'
$packageDir = Join-Path $distRoot $packageName
$archivePath = Join-Path $distRoot ($packageName + '.zip')
$tempRoot = Join-Path $repoRoot 'tmp\ampr-pack-distribution'
$venvRoot = Join-Path $tempRoot 'venv'
$venvPython = Join-Path $venvRoot 'Scripts\python.exe'
$pyinstallerDist = Join-Path $tempRoot 'pyinstaller-dist'
$pyinstallerWork = Join-Path $tempRoot 'pyinstaller-work'

function Assert-ManagedOutputPath([string]$Path) {
    $full = [System.IO.Path]::GetFullPath($Path)
    $managedRoot = [System.IO.Path]::GetFullPath($distRoot) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($managedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to replace output outside $distRoot`: $full"
    }
}

function Remove-ManagedOutput([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    if (-not $Force) {
        throw "Output already exists: $Path. Re-run with -Force to replace it."
    }
    Assert-ManagedOutputPath $Path
    Remove-Item -LiteralPath $Path -Recurse -Force
}

New-Item -ItemType Directory -Path $distRoot -Force | Out-Null
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
Remove-ManagedOutput $packageDir
Remove-ManagedOutput $archivePath

if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($null -ne $pyLauncher) {
        & $pyLauncher.Source -3 -m venv $venvRoot
    } else {
        $python = Get-Command python -ErrorAction Stop
        & $python.Source -m venv $venvRoot
    }
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to create the Python build environment.'
    }
}

$version = & $venvPython -c "import sys; print('.'.join(map(str, sys.version_info[:3])))"
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to run Python from the build environment.'
}
$majorMinor = [Version]$version
if ($majorMinor -lt [Version]'3.11') {
    throw "Python 3.11 or newer is required; build environment is $version"
}
$pointerBits = & $venvPython -c "import struct; print(struct.calcsize('P') * 8)"
if ($LASTEXITCODE -ne 0 -or $pointerBits -ne '64') {
    throw "A 64-bit Python build environment is required; detected $pointerBits-bit"
}

if (-not $SkipDependencyInstall) {
    & $venvPython -m pip install --disable-pip-version-check -r (Join-Path $PSScriptRoot 'requirements-pack-build.txt')
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to install distribution build dependencies.'
    }
}

try {
    & $venvPython -c "import PyInstaller, lz4.block, tkinter"
    if ($LASTEXITCODE -ne 0) {
        throw 'PyInstaller, lz4 and Tkinter must be available in the build environment.'
    }

    if (Test-Path -LiteralPath $pyinstallerDist) {
        Remove-Item -LiteralPath $pyinstallerDist -Recurse -Force
    }
    if (Test-Path -LiteralPath $pyinstallerWork) {
        Remove-Item -LiteralPath $pyinstallerWork -Recurse -Force
    }
    New-Item -ItemType Directory -Path $pyinstallerDist -Force | Out-Null
    New-Item -ItemType Directory -Path $pyinstallerWork -Force | Out-Null

    & $venvPython -m PyInstaller `
        --noconfirm `
        --clean `
        --onefile `
        --console `
        --noupx `
        --name ampr_pack_gui `
        --distpath $pyinstallerDist `
        --workpath $pyinstallerWork `
        --specpath $pyinstallerWork `
        --hidden-import lz4.block `
        (Join-Path $PSScriptRoot 'ampr_pack_gui.py')
    if ($LASTEXITCODE -ne 0) {
        throw 'PyInstaller failed.'
    }

    $builtExe = Join-Path $pyinstallerDist 'ampr_pack_gui.exe'
    if (-not (Test-Path -LiteralPath $builtExe -PathType Leaf)) {
        throw "Expected executable was not created: $builtExe"
    }

    New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
    $pythonToolsDir = Join-Path $packageDir 'python-tools'
    New-Item -ItemType Directory -Path $pythonToolsDir -Force | Out-Null
    Copy-Item -LiteralPath $builtExe -Destination (Join-Path $packageDir 'ampr_pack_gui.exe')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'docs\AMPR_PACK_DISTRIBUTION_README_EN.md') -Destination (Join-Path $packageDir 'README_EN.md')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'docs\AMPR_PACK_DISTRIBUTION_README_RU.md') -Destination (Join-Path $packageDir 'README_RU.md')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'docs\ASSET_PACK_WORKFLOW_EN.md') -Destination (Join-Path $packageDir 'USER_GUIDE_EN.md')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'docs\ASSET_PACK_WORKFLOW_RU.md') -Destination (Join-Path $packageDir 'USER_GUIDE_RU.md')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'ampr_pack.example.toml') -Destination $packageDir
    Copy-Item -LiteralPath (Join-Path $repoRoot 'third_party\lz4\LICENSE') -Destination (Join-Path $packageDir 'LICENSE-LZ4.txt')

    $pythonTools = @(
        'ampr_pack_gui.py',
        'ampr_pack.py',
        'ampr_pack_profile.py',
        'ampr_pack_format.py',
        'convert_ampr_pack_v3.py',
        'parse_ampr_command_log.py',
        'build_ampr_index.py',
        'analyze_ampr_log.py',
        'requirements-pack.txt'
    )
    foreach ($name in $pythonTools) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $pythonToolsDir
    }

    $exe = Join-Path $packageDir 'ampr_pack_gui.exe'
    $toolVersion = & $exe --internal-pack --version
    if ($LASTEXITCODE -ne 0 -or -not $toolVersion) {
        throw 'The packaged executable failed its embedded pack-tool smoke test.'
    }

    $commit = 'unknown'
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($null -ne $git) {
        $candidateCommit = & $git.Source -C $repoRoot rev-parse --short=12 HEAD 2>$null
        if ($LASTEXITCODE -eq 0 -and $candidateCommit) {
            $commit = $candidateCommit
        }
    }
    @(
        "Package: $packageName",
        "Created: $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))",
        "Commit: $commit",
        "Python: $version",
        "Embedded pack tool: $toolVersion"
    ) | Set-Content -LiteralPath (Join-Path $packageDir 'BUILD_INFO.txt') -Encoding utf8

    if (-not $NoArchive) {
        Compress-Archive -LiteralPath $packageDir -DestinationPath $archivePath -CompressionLevel Optimal
    }

    $hash = Get-FileHash -LiteralPath $exe -Algorithm SHA256
    Write-Host "Distribution: $packageDir"
    if (-not $NoArchive) {
        Write-Host "Archive:      $archivePath"
    }
    Write-Host "Executable:   $($hash.Hash)  $($hash.Path)"
} finally {
    # Keep the reusable venv, but remove transient PyInstaller products.
    if (Test-Path -LiteralPath $pyinstallerDist) {
        Remove-Item -LiteralPath $pyinstallerDist -Recurse -Force
    }
    if (Test-Path -LiteralPath $pyinstallerWork) {
        Remove-Item -LiteralPath $pyinstallerWork -Recurse -Force
    }
}
