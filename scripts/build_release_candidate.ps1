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
if ($SkipTests) {
    throw "SkipTests is forbidden for a release candidate. Use individual developer checks instead."
}

$ReparsePoint = [System.IO.FileAttributes]::ReparsePoint

function Assert-RegularNonReparseFile([string]$Path) {
    $Item = Get-Item -LiteralPath $Path -Force
    if ($Item.PSIsContainer -or (($Item.Attributes -band $ReparsePoint) -ne 0)) {
        throw "Release input must be a regular non-reparse file: $Path"
    }
}

function Assert-SafeDirectory([string]$Path) {
    $Item = Get-Item -LiteralPath $Path -Force
    if (-not $Item.PSIsContainer -or (($Item.Attributes -band $ReparsePoint) -ne 0)) {
        throw "Release directory may not be a reparse point: $Path"
    }
}

function Test-RegularExecutable([string]$Path) {
    $Item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    return (
        $null -ne $Item -and
        -not $Item.PSIsContainer -and
        (($Item.Attributes -band $ReparsePoint) -eq 0)
    )
}

function Resolve-Python {
    $Candidates = @(
        (Join-Path $env:SystemRoot "py.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Launcher\py.exe")
    )
    foreach ($Candidate in $Candidates) {
        if (-not (Test-RegularExecutable $Candidate)) { continue }
        try {
            & $Candidate -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)"
            if ($LASTEXITCODE -eq 0) {
                return @{ Exe = $Candidate; Prefix = @("-3") }
            }
        } catch {}
    }

    $Roots = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Python"),
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)}
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
    $PythonCandidates = @()
    foreach ($CandidateRoot in $Roots) {
        if (-not (Test-Path -LiteralPath $CandidateRoot)) { continue }
        $PythonCandidates += Get-ChildItem -LiteralPath $CandidateRoot -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "Python3*" -and (($_.Attributes -band $ReparsePoint) -eq 0) } |
            ForEach-Object { Join-Path $_.FullName "python.exe" }
    }
    foreach ($Candidate in ($PythonCandidates | Sort-Object -Descending)) {
        if (-not (Test-RegularExecutable $Candidate)) { continue }
        & $Candidate -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)"
        if ($LASTEXITCODE -eq 0) {
            return @{ Exe = $Candidate; Prefix = @() }
        }
    }
    throw "Python 3.11 or newer from a fixed installation path is required to build the release candidate."
}

function Resolve-TrustedGit {
    $Candidates = @(
        (Join-Path $env:ProgramFiles "Git\cmd\git.exe"),
        (Join-Path $env:ProgramFiles "Git\bin\git.exe")
    )
    if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
        $Candidates += Join-Path ${env:ProgramFiles(x86)} "Git\cmd\git.exe"
        $Candidates += Join-Path ${env:ProgramFiles(x86)} "Git\bin\git.exe"
    }
    foreach ($Candidate in $Candidates) {
        if (Test-RegularExecutable $Candidate) { return $Candidate }
    }
    throw "Git for Windows from Program Files is required to build a release candidate."
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

function Invoke-TrustedGit([string[]]$Arguments) {
    & $script:TrustedGit @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Git command failed with exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
    }
}

function Assert-PowerShellScriptsParse {
    $Failures = @()
    foreach ($Script in Get-ChildItem -LiteralPath (Join-Path $Root "scripts") -Filter "*.ps1" -File -Recurse) {
        $Tokens = $null
        $Errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile(
            $Script.FullName,
            [ref]$Tokens,
            [ref]$Errors
        ) | Out-Null
        foreach ($ParseError in @($Errors)) {
            $Failures += (
                "$($Script.FullName):$($ParseError.Extent.StartLineNumber): " +
                $ParseError.Message
            )
        }
    }
    if ($Failures.Count -gt 0) {
        throw "PowerShell parsing failed:`n$($Failures -join "`n")"
    }
}

$PyprojectPath = Join-Path $Root "pyproject.toml"
Assert-RegularNonReparseFile $PyprojectPath
$Pyproject = Get-Content -LiteralPath $PyprojectPath -Raw
$VersionMatch = [regex]::Match($Pyproject, '(?m)^version\s*=\s*"([^"]+)"\s*$')
if (-not $VersionMatch.Success) {
    throw "Could not determine the project version from pyproject.toml."
}
$Pep440Version = $VersionMatch.Groups[1].Value
$DisplayVersion = [regex]::Replace($Pep440Version, 'a([0-9]+)$', '-alpha.$1')
$DisplayVersion = [regex]::Replace($DisplayVersion, 'b([0-9]+)$', '-beta.$1')
$DisplayVersion = [regex]::Replace($DisplayVersion, 'rc([0-9]+)$', '-rc.$1')
$ArchiveName = "quietward-v${DisplayVersion}-source.zip"
$ChecksumName = "${ArchiveName}.sha256"
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$TemporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("quietward-release-" + [guid]::NewGuid().ToString("N"))
$BuildOne = Join-Path $TemporaryRoot "build-one.zip"
$BuildTwo = Join-Path $TemporaryRoot "build-two.zip"
$Runtime = Resolve-Python
$TrustedGit = Resolve-TrustedGit
$GitGlobal = [System.IO.Path]::GetTempFileName()

New-Item -ItemType Directory -Force -Path $TemporaryRoot | Out-Null
Assert-SafeDirectory $TemporaryRoot
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
Assert-SafeDirectory $OutputDirectory

$FinalArchive = Join-Path $OutputDirectory $ArchiveName
$FinalChecksum = Join-Path $OutputDirectory $ChecksumName
if ((Test-Path -LiteralPath $FinalArchive) -or (Test-Path -LiteralPath $FinalChecksum)) {
    throw "Release output already exists; refusing to overwrite it. Remove or archive the prior candidate explicitly."
}

try {
    Push-Location $Root
    $PreviousPythonPath = $env:PYTHONPATH
    $PreviousGitConfigNoSystem = $env:GIT_CONFIG_NOSYSTEM
    $PreviousGitConfigGlobal = $env:GIT_CONFIG_GLOBAL
    $PreviousGitOptionalLocks = $env:GIT_OPTIONAL_LOCKS
    $SourcePath = Join-Path $Root "src"
    $env:PYTHONPATH = $SourcePath
    $env:GIT_CONFIG_NOSYSTEM = "1"
    $env:GIT_CONFIG_GLOBAL = $GitGlobal
    $env:GIT_OPTIONAL_LOCKS = "0"
    try {
        $InitialCommitOutput = & $TrustedGit -c core.fsmonitor=false -c core.untrackedCache=false -C $Root rev-parse --verify "HEAD^{commit}" 2>$null
        if ($LASTEXITCODE -ne 0 -or $null -eq $InitialCommitOutput) {
            throw "Could not freeze the exact release commit."
        }
        $InitialCommit = ($InitialCommitOutput | Select-Object -First 1).Trim()

        Assert-PowerShellScriptsParse
        Invoke-TrustedGit @("-C", $Root, "diff", "--check", "HEAD", "--")

        # The public v0.5 gate runs the full repository tests, compilation,
        # static observation-only safety audit, public release audit,
        # deterministic double build, and both archive verifications.
        Invoke-Python $Runtime @("scripts/validate_migrated_release.py", "--root", $Root, "--pretty")

        Invoke-Python $Runtime @("scripts/build_release_bundle.py", $BuildOne, "--root", $Root)
        Invoke-Python $Runtime @("scripts/build_release_bundle.py", $BuildTwo, "--root", $Root)
        Invoke-Python $Runtime @("scripts/verify_release_bundle.py", $BuildOne)
        Invoke-Python $Runtime @("scripts/verify_release_bundle.py", $BuildTwo)

        $HashOne = (Get-FileHash -Algorithm SHA256 -LiteralPath $BuildOne).Hash.ToLowerInvariant()
        $HashTwo = (Get-FileHash -Algorithm SHA256 -LiteralPath $BuildTwo).Hash.ToLowerInvariant()
        if ($HashOne -ne $HashTwo) {
            throw "Deterministic build failed: the two archive hashes differ."
        }

        [System.IO.File]::Copy($BuildOne, $FinalArchive, $false)
        $FinalHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $FinalArchive).Hash.ToLowerInvariant()
        if ($FinalHash -ne $HashOne) {
            throw "The copied release archive does not match the validated deterministic build."
        }

        $ChecksumLine = "{0}  {1}`r`n" -f $FinalHash, $ArchiveName
        $ChecksumBytes = [System.Text.Encoding]::ASCII.GetBytes($ChecksumLine)
        $ChecksumStream = [System.IO.File]::Open(
            $FinalChecksum,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        try {
            $ChecksumStream.Write($ChecksumBytes, 0, $ChecksumBytes.Length)
            $ChecksumStream.Flush($true)
        } finally {
            $ChecksumStream.Dispose()
        }

        Invoke-Python $Runtime @("scripts/verify_release_bundle.py", $FinalArchive)
        $RecordedChecksum = (Get-Content -LiteralPath $FinalChecksum -Raw).Trim()
        if ($RecordedChecksum -ne ("{0}  {1}" -f $FinalHash, $ArchiveName)) {
            throw "The release checksum sidecar does not exactly match the final archive."
        }
        $IndependentHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $FinalArchive).Hash.ToLowerInvariant()
        if ($IndependentHash -ne $FinalHash) {
            throw "Independent final checksum recomputation failed."
        }

        $FinalCommitOutput = & $TrustedGit -c core.fsmonitor=false -c core.untrackedCache=false -C $Root rev-parse --verify "HEAD^{commit}" 2>$null
        if ($LASTEXITCODE -ne 0 -or $null -eq $FinalCommitOutput) {
            throw "Could not verify the final release commit."
        }
        $FinalCommit = ($FinalCommitOutput | Select-Object -First 1).Trim()
        if ($FinalCommit -ne $InitialCommit) {
            throw "The release checkout commit changed during validation."
        }
        Invoke-TrustedGit @("-C", $Root, "diff", "--quiet", "--no-ext-diff", "HEAD", "--")

        $Result = [ordered]@{
            decision = "PASS"
            version = $DisplayVersion
            commit = $FinalCommit
            archive = $FinalArchive
            checksum_file = $FinalChecksum
            sha256 = $FinalHash
            independent_sha256 = $IndependentHash
            bytes = (Get-Item -LiteralPath $FinalArchive).Length
            deterministic_builds = 2
            tests_skipped = $false
            powershell_parse = "PASS"
            git_diff_check = "PASS"
            actions_executed = 0
        }
        $Result | ConvertTo-Json -Depth 5
    }
    finally {
        if ($null -eq $PreviousPythonPath) { Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue } else { $env:PYTHONPATH = $PreviousPythonPath }
        if ($null -eq $PreviousGitConfigNoSystem) { Remove-Item Env:GIT_CONFIG_NOSYSTEM -ErrorAction SilentlyContinue } else { $env:GIT_CONFIG_NOSYSTEM = $PreviousGitConfigNoSystem }
        if ($null -eq $PreviousGitConfigGlobal) { Remove-Item Env:GIT_CONFIG_GLOBAL -ErrorAction SilentlyContinue } else { $env:GIT_CONFIG_GLOBAL = $PreviousGitConfigGlobal }
        if ($null -eq $PreviousGitOptionalLocks) { Remove-Item Env:GIT_OPTIONAL_LOCKS -ErrorAction SilentlyContinue } else { $env:GIT_OPTIONAL_LOCKS = $PreviousGitOptionalLocks }
        Pop-Location
    }
}
catch {
    if (Test-Path -LiteralPath $FinalArchive) { Remove-Item -LiteralPath $FinalArchive -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $FinalChecksum) { Remove-Item -LiteralPath $FinalChecksum -Force -ErrorAction SilentlyContinue }
    throw
}
finally {
    Remove-Item -LiteralPath $TemporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $GitGlobal -Force -ErrorAction SilentlyContinue
}
