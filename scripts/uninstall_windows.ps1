[CmdletBinding()]
param(
    [switch]$RemoveData,
    [switch]$RemoveConfiguration
)

$ErrorActionPreference = "Stop"
$Target = Join-Path $PSScriptRoot "uninstall_windows_preview.ps1"
if (-not (Test-Path -LiteralPath $Target)) {
    throw "Windows uninstaller component is missing: $Target"
}
& $Target @PSBoundParameters
if (-not $?) { exit 1 }
