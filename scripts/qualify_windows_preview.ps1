[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $HOME ".config\quietward\config.json"),
    [string]$OutputPath = (Join-Path $env:LOCALAPPDATA "QuietWard\state\windows-preview-qualification.json")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProductRoot = Join-Path $env:LOCALAPPDATA "QuietWard"
$QuietWardExe = Join-Path $ProductRoot "venv\Scripts\python.exe"
$TaskName = "QuietWard"

if (-not (Test-Path $QuietWardExe)) {
    throw "QuietWard is not installed at $QuietWardExe"
}
if (-not (Test-Path $ConfigPath)) {
    throw "QuietWard configuration is missing: $ConfigPath"
}

$DoctorText = & $QuietWardExe -m quietward doctor --config $ConfigPath --pretty
$DoctorExit = $LASTEXITCODE
$DiagnoseText = & $QuietWardExe -m quietward diagnose --config $ConfigPath --pretty
$DiagnoseExit = $LASTEXITCODE

$Doctor = $null
$Diagnose = $null
try { $Doctor = $DoctorText | ConvertFrom-Json } catch {}
try { $Diagnose = $DiagnoseText | ConvertFrom-Json } catch {}

$Dashboard = $null
$DashboardError = $null
try {
    $Dashboard = Invoke-RestMethod -Uri "http://127.0.0.1:8765/api/overview?limit=250" -TimeoutSec 5
} catch {
    $DashboardError = $_.Exception.Message
}

$Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$TaskInfo = $null
if ($null -ne $Task) {
    $TaskInfo = Get-ScheduledTaskInfo -TaskName $TaskName
}

$CollectorVersion = $null
$CollectorErrors = @()
$ActionsExecuted = $null
$EvidenceValid = $false
$OpenUrgent = 0
if ($null -ne $Dashboard) {
    $CollectorVersion = $Dashboard.collector.version
    $CollectorErrors = @($Dashboard.collector_errors)
    $ActionsExecuted = $Dashboard.actions_executed
    $EvidenceValid = [bool]$Dashboard.summary.evidence_chain.valid
    $OpenUrgent = @(
        $Dashboard.findings | Where-Object {
            ($_.severity -eq "critical" -or $_.severity -eq "high") -and
            ($null -eq $_.review.state -or $_.review.state -eq "open" -or $_.review.state -eq "acknowledged")
        }
    ).Count
}

$Checks = [ordered]@{
    doctor_pass = ($DoctorExit -eq 0 -and $null -ne $Doctor -and $Doctor.decision -eq "PASS")
    diagnose_pass = ($DiagnoseExit -eq 0 -and $null -ne $Diagnose -and $Diagnose.decision -eq "PASS")
    scheduled_task_present = ($null -ne $Task)
    scheduled_task_enabled = ($null -ne $Task -and $Task.State -ne "Disabled")
    dashboard_available = ($null -ne $Dashboard)
    windows_collector_active = ($null -ne $CollectorVersion -and $CollectorVersion -like "windows-read-only-*")
    evidence_chain_valid = $EvidenceValid
    actions_executed_zero = ($ActionsExecuted -eq 0)
    collector_error_count = $CollectorErrors.Count
    open_high_or_critical = $OpenUrgent
}

$BlockingChecks = @(
    "doctor_pass",
    "scheduled_task_present",
    "scheduled_task_enabled",
    "dashboard_available",
    "windows_collector_active",
    "evidence_chain_valid",
    "actions_executed_zero"
)
$Failed = @($BlockingChecks | Where-Object { -not [bool]$Checks[$_] })
$Decision = if ($Failed.Count -eq 0) { "PASS" } else { "FAIL" }

$Report = [ordered]@{
    qualification = "quietward-windows-preview-v1"
    observed_at = [DateTime]::UtcNow.ToString("o")
    decision = $Decision
    failed_checks = $Failed
    checks = $Checks
    task = if ($null -eq $TaskInfo) { $null } else {
        [ordered]@{
            last_run_time = $TaskInfo.LastRunTime
            last_task_result = $TaskInfo.LastTaskResult
            next_run_time = $TaskInfo.NextRunTime
        }
    }
    collector_errors = $CollectorErrors
    dashboard_error = $DashboardError
    safety = [ordered]@{
        actions_executed = if ($null -eq $ActionsExecuted) { "unknown" } else { $ActionsExecuted }
        system_state_modified_by_qualification = $false
        service_restarted_by_qualification = $false
    }
}

$OutputDir = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$Json = $Report | ConvertTo-Json -Depth 8
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutputPath, $Json, $Utf8NoBom)

$Report | ConvertTo-Json -Depth 8
Write-Host "Qualification report: $OutputPath"
exit $(if ($Decision -eq "PASS") { 0 } else { 1 })
