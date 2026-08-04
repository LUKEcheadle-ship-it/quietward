[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $Root "dist"
}

function Resolve-Python {
    $Launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($null -ne $Launcher) {
        & $Launcher.Source -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)"
        if ($LASTEXITCODE -eq 0) {
            return @{ Exe = $Launcher.Source; Prefix = @("-3") }
        }
    }
    $Python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($null -ne $Python) {
        & $Python.Source -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)"
        if ($LASTEXITCODE -eq 0) {
            return @{ Exe = $Python.Source; Prefix = @() }
        }
    }
    throw "Python 3.11 or newer is required to build the release candidate."
}

function Invoke-Python([hashtable]$Runtime, [string[]]$Arguments) {
    $AllArguments = @()
    $AllArguments += $Runtime.Prefix
    $AllArguments += $Arguments
    & $Runtime.Exe @AllArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed with exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
    }
}

$Pyproject = Get-Content -LiteralPath (Join-Path $Root "pyproject.toml") -Raw
$VersionMatch = [regex]::Match($Pyproject, '(?m)^version\s*=\s*"([^"]+)"\s*$')
if (-not $VersionMatch.Success) {
    throw "Could not determine the project version from pyproject.toml."
}
$Pep440Version = $VersionMatch.Groups[1].Value
$DisplayVersion = [regex]::Replace($Pep440Version, 'a([0-9]+)$', '-alpha.$1')
$ArchiveName = "quietward-v${DisplayVersion}-source.zip"
$ChecksumName = "${ArchiveName}.sha256"
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$TemporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("quietward-release-" + [guid]::NewGuid().ToString("N"))
$BuildOne = Join-Path $TemporaryRoot "build-one.zip"
$BuildTwo = Join-Path $TemporaryRoot "build-two.zip"
$Runtime = Resolve-Python

New-Item -ItemType Directory -Force -Path $TemporaryRoot | Out-Null
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

try {
    Push-Location $Root
    $PreviousPythonPath = $env:PYTHONPATH
    $SourcePath = Join-Path $Root "src"
    $env:PYTHONPATH = if ([string]::IsNullOrWhiteSpace($PreviousPythonPath)) {
        $SourcePath
    } else {
        $SourcePath + [System.IO.Path]::PathSeparator + $PreviousPythonPath
    }
    try {
        if (-not $SkipTests) {
            Invoke-Python $Runtime @("-m", "unittest", "discover", "-s", "tests", "-v")
            Invoke-Python $Runtime @("-m", "compileall", "-q", "src", "tests", "scripts")
            Invoke-Python $Runtime @("scripts/public_release_audit.py", ".")
        }

        Invoke-Python $Runtime @("scripts/build_release_bundle.py", $BuildOne, "--root", $Root)
        Invoke-Python $Runtime @("scripts/build_release_bundle.py", $BuildTwo, "--root", $Root)

        $HashOne = (Get-FileHash -Algorithm SHA256 -LiteralPath $BuildOne).Hash.ToLowerInvariant()
        $HashTwo = (Get-FileHash -Algorithm SHA256 -LiteralPath $BuildTwo).Hash.ToLowerInvariant()
        if ($HashOne -ne $HashTwo) {
            throw "Deterministic build failed: the two archive hashes differ."
        }

        $FinalArchive = Join-Path $OutputDirectory $ArchiveName
        $FinalChecksum = Join-Path $OutputDirectory $ChecksumName
        Copy-Item -LiteralPath $BuildOne -Destination $FinalArchive -Force
        Set-Content -LiteralPath $FinalChecksum -Value ("{0}  {1}" -f $HashOne, $ArchiveName) -Encoding Ascii

        Invoke-Python $Runtime @("scripts/verify_release_bundle.py", $FinalArchive)

        $Commit = "unavailable"
        $Git = Get-Command git.exe -ErrorAction SilentlyContinue
        if ($null -eq $Git) { $Git = Get-Command git -ErrorAction SilentlyContinue }
        if ($null -ne $Git) {
            $CommitOutput = & $Git.Source -C $Root rev-parse HEAD 2>$null
            if ($LASTEXITCODE -eq 0 -and $null -ne $CommitOutput) {
                $Commit = ($CommitOutput | Select-Object -First 1).Trim()
            }
        }

        $Result = [ordered]@{
            decision = "PASS"
            version = $DisplayVersion
            commit = $Commit
            archive = $FinalArchive
            checksum_file = $FinalChecksum
            sha256 = $HashOne
            bytes = (Get-Item -LiteralPath $FinalArchive).Length
            deterministic_builds = 2
            tests_skipped = [bool]$SkipTests
            actions_executed = 0
        }
        $Result | ConvertTo-Json -Depth 5
    }
    finally {
        $env:PYTHONPATH = $PreviousPythonPath
        Pop-Location
    }
}
finally {
    Remove-Item -LiteralPath $TemporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}
