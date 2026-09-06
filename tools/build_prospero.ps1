[CmdletBinding()]
param(
    [ValidateSet('Both', 'LooseStdio', 'PackedStdio')]
    [string]$Profile = 'Both',

    [ValidateSet('Release', 'Debug', 'Both')]
    [string]$BuildType = 'Release',

    [switch]$Rebuild,

    [string]$MSBuildPath = 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$solutionPath = Join-Path $repositoryRoot 'libSceAmpr.sln'

if (-not (Test-Path -LiteralPath $MSBuildPath -PathType Leaf)) {
    throw "MSBuild was not found at '$MSBuildPath'. Pass the installed path with -MSBuildPath."
}

$profiles = if ($Profile -eq 'Both') {
    @('LooseStdio', 'PackedStdio')
} else {
    @($Profile)
}

$buildTypes = if ($BuildType -eq 'Both') {
    @('Release', 'Debug')
} else {
    @($BuildType)
}

$target = if ($Rebuild) { 'Rebuild' } else { 'Build' }

Push-Location $repositoryRoot
try {
    foreach ($currentBuildType in $buildTypes) {
        foreach ($currentProfile in $profiles) {
        $configuration = "${currentBuildType}Hooks$currentProfile"
        $logPath = Join-Path $repositoryRoot "build-$configuration.log"
        $arguments = @(
            $solutionPath
            "/t:$target"
            '/m'
            "/p:Configuration=$configuration"
            '/p:Platform=Prospero'
            '/v:minimal'
        )

        Write-Host "Building $configuration ($target)..."
        & $MSBuildPath @arguments *> $logPath
        $buildExitCode = $LASTEXITCODE
        if ($buildExitCode -ne 0) {
            Get-Content -LiteralPath $logPath -Tail 200
            throw "$configuration build failed with exit code $buildExitCode. See '$logPath'."
        }

        $outputDirectory = Join-Path $repositoryRoot "out\Prospero_$configuration"
        foreach ($artifactName in @('libSceAmpr.prx', 'libSceAmpr.sprx', 'libSceAmpr_stub.a', 'libSceAmpr_stub_weak.a')) {
            $artifactPath = Join-Path $outputDirectory $artifactName
            if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) {
                throw "$configuration did not produce '$artifactPath'. See '$logPath'."
            }
        }

        Write-Host "Built $configuration -> $outputDirectory"
        }
    }
} finally {
    Pop-Location
}
