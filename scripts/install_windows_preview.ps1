[CmdletBinding()]
param(
    [switch]$EnableSecurityLog,
    [switch]$NoStart,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$TaskName = "QuietWard"
$ProductRoot = Join-Path $env:LOCALAPPDATA "QuietWard"
$VenvDir = Join-Path $ProductRoot "venv"
$StateDir = Join-Path $ProductRoot "state"
$KeyDir = Join-Path $ProductRoot "keys"
$ConfigDir = Join-Path $HOME ".config\quietward"
$ConfigPath = Join-Path $ConfigDir "config.json"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Desktop = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $Desktop "QuietWard Dashboard.url"
$CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Resolve-Python {
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($null -ne $py) {
        try {
            & $py.Source -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)"
            if ($LASTEXITCODE -eq 0) {
                return @{
                    Exe = $py.Source
                    Prefix = @("-3")
                }
            }
        } catch {}
    }

    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($null -ne $python) {
        & $python.Source -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)"
        if ($LASTEXITCODE -eq 0) {
            return @{
                Exe = $python.Source
                Prefix = @()
            }
        }
    }

    throw "Python 3.11 or newer is required. Install Python from python.org, enable the Python launcher, then rerun this script."
}

function Protect-Directory([string]$Path) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    & icacls.exe $Path /inheritance:r /grant:r "${CurrentIdentity}:(OI)(CI)F" "SYSTEM:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not protect directory ACL: $Path"
    }
}

function Protect-File([string]$Path) {
    & icacls.exe $Path /inheritance:r /grant:r "${CurrentIdentity}:F" "SYSTEM:F" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not protect file ACL: $Path"
    }
}

function Stop-InstalledQuietWard {
    $ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $ExistingTask) { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue }
    $LockPath = Join-Path $StateDir "service.lock"
    if (-not (Test-Path $LockPath)) { return }
    $LockContent = Get-Content -LiteralPath $LockPath -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($LockContent)) { return }
    $RawPid = $LockContent.Trim()
    $ParsedPid = 0
    if (-not [int]::TryParse($RawPid, [ref]$ParsedPid)) { return }
    $Process = Get-Process -Id $ParsedPid -ErrorAction SilentlyContinue
    if ($null -eq $Process) { return }
    $ProcessPath = ""
    try { $ProcessPath = $Process.Path } catch {}
    $ExpectedPrefix = (Join-Path $VenvDir "Scripts").ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($ProcessPath) -or -not $ProcessPath.ToLowerInvariant().StartsWith($ExpectedPrefix)) {
        throw "The QuietWard lock references a process outside the QuietWard virtual environment; refusing to stop it."
    }
    Stop-Process -Id $ParsedPid -Force
    $Process.WaitForExit(5000) | Out-Null
}

function Write-RandomKey([string]$Path) {
    if (Test-Path $Path) {
        return
    }
    $bytes = New-Object byte[] 64
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    [System.IO.File]::WriteAllBytes($Path, $bytes)
    Protect-File $Path
}

if (-not (Test-Path (Join-Path $RepoRoot "pyproject.toml"))) {
    throw "Run this script from a complete QuietWard repository checkout."
}

Write-Step "Preparing private application directories"
Protect-Directory $ProductRoot
Protect-Directory $StateDir
Protect-Directory $KeyDir
Protect-Directory $ConfigDir

$PrivacyKey = Join-Path $KeyDir "privacy-identity.key"
$EvidenceKey = Join-Path $KeyDir "evidence-signing.key"
Write-RandomKey $PrivacyKey
Write-RandomKey $EvidenceKey

Write-Step "Creating the isolated Python environment"
Stop-InstalledQuietWard
$Python = Resolve-Python
if (-not (Test-Path (Join-Path $VenvDir "Scripts\python.exe"))) {
    $VenvArguments = @($Python.Prefix) + @("-m", "venv", $VenvDir)
    & $Python.Exe $VenvArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Virtual environment creation failed."
    }
}

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$QuietWardExe = $VenvPython
$QuietWardPrefix = @("-m", "quietward")

Write-Step "Installing QuietWard from this checkout"
$SitePackages = (& $VenvPython -c "import sysconfig; print(sysconfig.get_paths()['purelib'])").Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($SitePackages)) {
    throw "Could not locate the virtual environment package directory."
}
$InstalledPackage = Join-Path $SitePackages "quietward"
if (Test-Path $InstalledPackage) {
    Remove-Item -LiteralPath $InstalledPackage -Recurse -Force
}
Copy-Item -LiteralPath (Join-Path $RepoRoot "src\quietward") -Destination $InstalledPackage -Recurse -Force
& $VenvPython -m quietward --help | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "QuietWard installation failed."
}

# An installer-authored package replacement is expected. Re-baseline self-integrity
# so the upgrade itself is not presented as a malware finding.
$DatabasePath = Join-Path $StateDir "quietward.sqlite3"
if (Test-Path $DatabasePath) {
    & $VenvPython -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('DELETE FROM metadata WHERE key=?', ('self_integrity_manifest',)); c.commit(); c.close()" $DatabasePath
    if ($LASTEXITCODE -ne 0) { throw "Could not refresh the QuietWard self-integrity baseline for the upgrade." }
}

Write-Step "Writing the Windows preview configuration"
$HostsFile = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
$SensitiveFiles = @()
if (Test-Path $HostsFile) {
    $SensitiveFiles += $HostsFile
}

$Config = [ordered]@{
    mode = "observe_only"
    state_dir = $StateDir
    collector = [ordered]@{
        type = "auto"
        interval_seconds = 60
        include_processes = $true
        include_listening_sockets = $true
        include_outbound_connections = $false
        include_auth_journal = [bool]$EnableSecurityLog
        include_docker = $true
        include_persistence = $true
        sensitive_files = $SensitiveFiles
        max_file_hash_bytes = 4194304
        max_persistence_entries = 2000
        max_docker_inspects = 50
        privacy_identity_key_path = $PrivacyKey
        persist_raw_process_arguments = $false
        persist_raw_source_addresses = $false
        persist_raw_destination_addresses = $false
        use_shell = $false
        use_sudo = $false
    }
    storage = [ordered]@{
        database_path = (Join-Path $StateDir "quietward.sqlite3")
        alert_log_path = (Join-Path $StateDir "alerts.jsonl")
        max_snapshots = 2000
        max_events = 100000
        max_findings = 25000
        retention_days = 30
        max_cycles = 2000
        max_scanner_runs = 10000
        evidence_signing_key_path = $EvidenceKey
    }
    service = [ordered]@{
        health_path = (Join-Path $StateDir "health.json")
        lock_path = (Join-Path $StateDir "service.lock")
        scanner_poll_seconds = 60
        stop_after_failures = 10
    }
    dashboard = [ordered]@{
        enabled = $true
        bind = "127.0.0.1"
        port = 8765
        allow_private_network_bind = $false
    }
    self_integrity = [ordered]@{
        enabled = $true
        extra_paths = @()
        max_files = 1000
        max_file_bytes = 8388608
    }
    tiny_model = [ordered]@{
        enabled = $true
    }
    micro_llm = [ordered]@{
        enabled = $false
        endpoint = "http://127.0.0.1:11434"
        timeout_seconds = 20
    }
    scanners = @()
    actions = [ordered]@{
        execute = $false
        require_human_approval = $true
    }
    network = [ordered]@{
        cloud_upload = $false
        public_listener = $false
    }
}

$ConfigJson = $Config | ConvertTo-Json -Depth 8
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ConfigPath, $ConfigJson, $Utf8NoBom)
Protect-File $ConfigPath

Write-Step "Running prerequisite and database checks"
& $QuietWardExe @QuietWardPrefix doctor --config $ConfigPath --pretty
if ($LASTEXITCODE -ne 0) {
    throw "QuietWard doctor reported a required failure. Review the output above."
}

Write-Step "Running the first observation cycle"
& $QuietWardExe @QuietWardPrefix run --config $ConfigPath --cycles 1 --no-dashboard
if ($LASTEXITCODE -ne 0) {
    throw "The first QuietWard cycle failed."
}

Write-Step "Registering automatic startup for the current Windows user"
$ActionArguments = "-m quietward run --config `"$ConfigPath`""
$Action = New-ScheduledTaskAction -Execute $QuietWardExe -Argument $ActionArguments
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $CurrentIdentity
$Principal = New-ScheduledTaskPrincipal -UserId $CurrentIdentity -LogonType Interactive -RunLevel Limited
$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Settings $Settings `
    -Description "QuietWard local observation-only security monitor" `
    -Force | Out-Null

@"
[InternetShortcut]
URL=http://127.0.0.1:8765/
"@ | Set-Content -LiteralPath $ShortcutPath -Encoding ASCII

if (-not $NoStart) {
    Write-Step "Starting QuietWard"
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 3
}

Write-Step "Checking the installed preview"
& $QuietWardExe @QuietWardPrefix diagnose --config $ConfigPath --pretty
$DiagnoseExit = $LASTEXITCODE

if (-not $NoBrowser -and -not $NoStart) {
    & $QuietWardExe @QuietWardPrefix open-dashboard --config $ConfigPath --pretty
}

Write-Host ""
Write-Host "QuietWard Windows preview installed." -ForegroundColor Green
Write-Host "Dashboard: http://127.0.0.1:8765/"
Write-Host "Configuration: $ConfigPath"
Write-Host "State: $StateDir"
Write-Host "Task: $TaskName"
Write-Host "Diagnostics: `"$QuietWardExe`" -m quietward diagnose --config `"$ConfigPath`" --pretty"
Write-Host "Security-log collection enabled: $([bool]$EnableSecurityLog)"
Write-Host "Actions executed by QuietWard: 0"

if ($DiagnoseExit -ne 0) {
    Write-Warning "Installation completed, but diagnostics require attention. Review the diagnostic output."
    exit 2
}
