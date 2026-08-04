[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $HOME ".config\quietward\config.json"),
    [string]$OutputPath = (Join-Path $env:LOCALAPPDATA "QuietWard\state\windows-qualification.json")
)

$ErrorActionPreference = "Stop"
$Target = Join-Path $PSScriptRoot "qualify_windows_preview.ps1"
if (-not (Test-Path -LiteralPath $Target)) {
    throw "Windows qualification component is missing: $Target"
}
& $Target -ConfigPath $ConfigPath -OutputPath $OutputPath
if (-not $?) { exit 1 }
