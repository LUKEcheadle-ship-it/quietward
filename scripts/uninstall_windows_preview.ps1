[CmdletBinding()]
param(
    [switch]$RemoveData,
    [switch]$RemoveConfiguration
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$TaskName = "QuietWard"
$ProductRoot = Join-Path $env:LOCALAPPDATA "QuietWard"
$VenvDir = Join-Path $ProductRoot "venv"
$StateDir = Join-Path $ProductRoot "state"
$KeyDir = Join-Path $ProductRoot "keys"
$ConfigDir = Join-Path $HOME ".config\quietward"
$LockPath = Join-Path $StateDir "service.lock"
$Desktop = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $Desktop "QuietWard Dashboard.url"

function Stop-QuietWardProcess {
    if (-not (Test-Path $LockPath)) {
        return
    }
    $RawPid = (Get-Content -LiteralPath $LockPath -Raw -ErrorAction SilentlyContinue).Trim()
    $ParsedPid = 0
    if (-not [int]::TryParse($RawPid, [ref]$ParsedPid)) {
        return
    }
    $Process = Get-Process -Id $ParsedPid -ErrorAction SilentlyContinue
    if ($null -eq $Process) {
        return
    }
    $ExpectedPrefix = (Join-Path $VenvDir "Scripts").ToLowerInvariant()
    $ProcessPath = ""
    try {
        $ProcessPath = $Process.Path
    } catch {}
    if ([string]::IsNullOrWhiteSpace($ProcessPath)) {
        Write-Warning "QuietWard process $ParsedPid is running but its executable path could not be verified; it was not stopped."
        return
    }
    if (-not $ProcessPath.ToLowerInvariant().StartsWith($ExpectedPrefix)) {
        Write-Warning "Lock PID $ParsedPid does not belong to the QuietWard virtual environment; it was not stopped."
        return
    }
    Stop-Process -Id $ParsedPid -Force
}

$Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $Task) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

Stop-QuietWardProcess

if (Test-Path $ShortcutPath) {
    Remove-Item -LiteralPath $ShortcutPath -Force
}

if (Test-Path $VenvDir) {
    Remove-Item -LiteralPath $VenvDir -Recurse -Force
}

if ($RemoveData -and (Test-Path $StateDir)) {
    Remove-Item -LiteralPath $StateDir -Recurse -Force
}

if ($RemoveConfiguration -and (Test-Path $ConfigDir)) {
    Remove-Item -LiteralPath $ConfigDir -Recurse -Force
}

if ($RemoveData -and $RemoveConfiguration -and (Test-Path $KeyDir)) {
    Remove-Item -LiteralPath $KeyDir -Recurse -Force
}

if ((Test-Path $ProductRoot) -and -not (Get-ChildItem -LiteralPath $ProductRoot -Force | Select-Object -First 1)) {
    Remove-Item -LiteralPath $ProductRoot -Force
}

Write-Host "QuietWard Windows preview removed." -ForegroundColor Green
Write-Host "Runtime data removed: $([bool]$RemoveData)"
Write-Host "Configuration removed: $([bool]$RemoveConfiguration)"
