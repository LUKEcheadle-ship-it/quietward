[CmdletBinding()]
param(
    [ValidateSet("primary", "fresh")]
    [string]$Role = "primary",
    [double]$DurationHours = 0,
    [string]$ConfigPath = (Join-Path $HOME ".config\quietward\config.json"),
    [string]$OutputDirectory = (Join-Path $env:LOCALAPPDATA "QuietWard\qualification\beta")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ProductRoot = Join-Path $env:LOCALAPPDATA "QuietWard"
$ConfigRoot = Join-Path $HOME ".config\quietward"
$InstalledPython = Join-Path $ProductRoot "venv\Scripts\python.exe"
$Provenance = Join-Path $ProductRoot "installation.json"
if (Test-Path $InstalledPython) {
    $Python = $InstalledPython
    $Prefix = @()
} else {
    $Launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($null -eq $Launcher) { throw "Python 3.11+ or an installed QuietWard runtime is required." }
    $Python = $Launcher.Source
    $Prefix = @("-3")
}
if ($DurationHours -le 0) {
    $DurationHours = if ($Role -eq "primary") { 72 } else { 2 }
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$Manifest = Join-Path $OutputDirectory ("beta-soak-{0}-manifest.json" -f $Role)
$RestartReport = Join-Path $OutputDirectory "windows-restart-state.json"
$ValidationReport = Join-Path $OutputDirectory "beta-validation.json"
$ProvenanceStart = Join-Path $OutputDirectory ("beta-provenance-{0}-start.json" -f $Role)
$InstalledPackage = Join-Path $ProductRoot "venv\Lib\site-packages\quietward"
$PreviousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = Join-Path $Root "src"

    $VerifyArguments = @()
    $VerifyArguments += $Prefix
    $VerifyArguments += @(
        (Join-Path $Root "scripts\verify_installation_provenance.py"),
        "--repo-root", $Root,
        "--provenance", $Provenance
    )
    & $Python @VerifyArguments
    if ($LASTEXITCODE -ne 0) { throw "Installed candidate does not match the checkout." }

    $CaptureArguments = @()
    $CaptureArguments += $Prefix
    $CaptureArguments += @(
        (Join-Path $Root "scripts\capture_beta_provenance.py"),
        "--repo-root", $Root,
        "--installed-package", $InstalledPackage,
        "--provenance", $Provenance,
        "--stage", "start",
        "--output", $ProvenanceStart
    )
    & $Python @CaptureArguments
    if ($LASTEXITCODE -ne 0) { throw "Start provenance capture failed." }

    $ValidationArguments = @()
    $ValidationArguments += $Prefix
    $ValidationArguments += @(
        (Join-Path $Root "scripts\run_beta_validation.py"),
        "--output", $ValidationReport
    )
    & $Python @ValidationArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Exact-commit beta validation failed. Review the private report: $ValidationReport"
    }

    $RestartArguments = @()
    $RestartArguments += $Prefix
    $RestartArguments += @(
        (Join-Path $Root "scripts\inspect_windows_restart_state.py"),
        "--history", $RestartReport,
        "--write-report", $RestartReport,
        "--protected-root", $Root,
        "--protected-root", $ProductRoot,
        "--protected-root", $ConfigRoot
    )
    & $Python @RestartArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Windows restart-state gate failed. Review the private restart report before retrying: $RestartReport"
    }
    $RestartState = Get-Content -LiteralPath $RestartReport -Raw | ConvertFrom-Json
    if ($RestartState.decision -notin @("PASS", "PASS_STALE", "PASS_EXTERNAL")) {
        throw "Windows restart-state decision is not allowed for beta start: $($RestartState.decision)"
    }
    if ([int]$RestartState.counts.active_protected -ne 0) {
        throw "A queued operation touches a QuietWard-protected path."
    }

    $Arguments = @()
    $Arguments += $Prefix
    $Arguments += @(
        (Join-Path $Root "scripts\beta_soak.py"),
        "start",
        "--config", $ConfigPath,
        "--manifest", $Manifest,
        "--role", $Role,
        "--duration-hours", $DurationHours,
        "--validation-report", $ValidationReport,
        "--host-state-report", $RestartReport
    )
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Beta soak start gate failed with exit code ${LASTEXITCODE}." }
} finally {
    $env:PYTHONPATH = $PreviousPythonPath
}
Write-Host "Beta soak started. Keep QuietWard and the host running normally." -ForegroundColor Green
Write-Host "Manifest: $Manifest"
Write-Host "Validation report: $ValidationReport"
Write-Host "Restart-state report: $RestartReport"
Write-Host "Restart-state decision: $($RestartState.decision)"
if ($RestartState.decision -eq "PASS_EXTERNAL") {
    Write-Warning ("External host maintenance remains queued ({0} active source(s)); QuietWard did not modify it." -f $RestartState.counts.active_external)
    Write-Warning "Do not restart the host during the soak unless you intentionally restart the campaign."
}
Write-Host "Required duration: $DurationHours hours"
