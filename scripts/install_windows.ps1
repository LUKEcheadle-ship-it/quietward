[CmdletBinding()]
param(
    [switch]$EnableSecurityLog,
    [switch]$NoStart,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$Target = Join-Path $PSScriptRoot "install_windows_preview.ps1"
if (-not (Test-Path -LiteralPath $Target)) {
    throw "Windows installer component is missing: $Target"
}
& $Target @PSBoundParameters
if (-not $?) { exit 1 }
