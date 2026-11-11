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
    $LockContent = Get-Content -LiteralPath $LockPath -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($LockContent)) {
        throw "The QuietWard lock is empty; refusing to remove a possibly active runtime."
    }
    $RawPid = $LockContent.Trim()
    $ParsedPid = 0
    if (-not [int]::TryParse($RawPid, [ref]$ParsedPid) -or $ParsedPid -le 0) {
        throw "The QuietWard lock does not contain a valid process ID; refusing to remove the runtime."
    }
    $Process = Get-Process -Id $ParsedPid -ErrorAction SilentlyContinue
    if ($null -eq $Process) {
        return
    }
    $ExpectedExecutable = Join-Path $VenvDir "Scripts\python.exe"
    $ProcessPath = ""
    try {
        # Pin the process identity before examining the executable path.
        $ProcessHandle = $Process.Handle
        if ($null -eq $ProcessHandle -or $ProcessHandle -eq [IntPtr]::Zero) {
            throw "The QuietWard process handle could not be verified."
        }
        $ProcessPath = $Process.Path
    } catch {}
    if ([string]::IsNullOrWhiteSpace($ProcessPath)) {
        throw "QuietWard process $ParsedPid could not be verified; refusing to stop it or remove the runtime."
    }
    if (-not [string]::Equals($ProcessPath, $ExpectedExecutable, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Lock PID $ParsedPid does not belong to the QuietWard virtual environment; refusing to stop it or remove the runtime."
    }
    Stop-Process -InputObject $Process -Force -ErrorAction Stop
    if (-not $Process.WaitForExit(5000)) {
        throw "The QuietWard process did not exit; refusing to remove the active runtime."
    }
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
