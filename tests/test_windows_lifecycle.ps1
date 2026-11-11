# Execute only the production stop functions with fake process/filesystem APIs.
# Never invoke the installer/uninstaller bodies or modify a task, ACL or runtime.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Root = Split-Path -Parent $PSScriptRoot
$VenvDir = Join-Path ([System.IO.Path]::GetTempPath()) 'quietward-fixture\venv'
$StateDir = Join-Path ([System.IO.Path]::GetTempPath()) 'quietward-fixture\state'
$LockPath = Join-Path $StateDir 'service.lock'
$TaskName = 'QuietWard-fixture'
$Expected = Join-Path $VenvDir 'Scripts\python.exe'
$script:Assertions = 0

function Test-Path { param($Path, $LiteralPath) return $script:Mock.Exists }
function Get-Content {
    [CmdletBinding()] param($LiteralPath, [switch]$Raw)
    if ($script:Mock.ReadError) { throw 'fixture read denied' }
    return $script:Mock.Content
}
function Get-ScheduledTask { [CmdletBinding()] param($TaskName) return $null }
function Stop-ScheduledTask { [CmdletBinding()] param($TaskName) throw 'unexpected task operation' }
function Get-Process { [CmdletBinding()] param($Id) return $script:Mock.Process }
function Stop-Process {
    [CmdletBinding()] param($InputObject, [switch]$Force)
    $script:Mock.Stops++
    if (-not [object]::ReferenceEquals($InputObject, $script:Mock.Process)) {
        throw 'stop did not retain the inspected process object'
    }
    if ($script:Mock.StopError) { throw 'fixture stop failed' }
}

function Reset-Fixture {
    $script:Mock = @{
        Exists = $true; Content = '12345'; ReadError = $false
        Stops = 0; StopError = $false; Exits = $true; Process = $null
    }
    $Process = [pscustomobject]@{ Path = $Expected; Handle = 42 }
    $Process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {
        param($Timeout)
        if ($Timeout -ne 5000) { throw 'unexpected wait bound' }
        return $script:Mock.Exits
    }
    $script:Mock.Process = $Process
}

function Check-Case {
    param([string]$Label, [scriptblock]$Configure, [bool]$ShouldThrow, [int]$Stops)
    Reset-Fixture
    & $Configure
    $Threw = $false
    try { & $script:FunctionName } catch { $Threw = $true }
    if ($Threw -ne $ShouldThrow -or $script:Mock.Stops -ne $Stops) {
        throw "$($script:FunctionName) / $Label failed: threw=$Threw, stops=$($script:Mock.Stops)"
    }
    $script:Assertions++
    Write-Host "PASS $($script:FunctionName): $Label"
}

foreach ($Spec in @(
    @('install_windows_preview.ps1', 'Stop-InstalledQuietWard'),
    @('uninstall_windows_preview.ps1', 'Stop-QuietWardProcess')
)) {
    $Tokens = $null; $Errors = $null
    $Ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $Root "scripts\$($Spec[0])"), [ref]$Tokens, [ref]$Errors
    )
    if ($Errors.Count) { throw ($Errors | Out-String) }
    $Name = $Spec[1]
    $Function = $Ast.Find({ param($Node)
        $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq $Name
    }, $true)
    if ($null -eq $Function) { throw "Missing production function: $Name" }
    . ([scriptblock]::Create($Function.Extent.Text))
    $script:FunctionName = $Name

    Check-Case 'missing lock' { $script:Mock.Exists = $false } $false 0
    Check-Case 'null lock' { $script:Mock.Content = $null } $true 0
    Check-Case 'blank lock' { $script:Mock.Content = '   ' } $true 0
    Check-Case 'invalid PID' { $script:Mock.Content = 'not-a-pid' } $true 0
    Check-Case 'negative PID' { $script:Mock.Content = '-1' } $true 0
    Check-Case 'zero PID' { $script:Mock.Content = '0' } $true 0
    Check-Case 'unreadable lock' { $script:Mock.ReadError = $true } $true 0
    Check-Case 'stale PID' { $script:Mock.Process = $null } $false 0
    Check-Case 'unavailable executable' { $script:Mock.Process.Path = '' } $true 0
    Check-Case 'sibling prefix' { $script:Mock.Process.Path = Join-Path $VenvDir 'Scripts-other\python.exe' } $true 0
    Check-Case 'different executable' { $script:Mock.Process.Path = Join-Path $VenvDir 'Scripts\other.exe' } $true 0
    Check-Case 'exact executable' {} $false 1
    Check-Case 'case-insensitive executable' { $script:Mock.Process.Path = $Expected.ToUpperInvariant() } $false 1
    Check-Case 'unavailable handle' {
        $script:Mock.Process.PSObject.Properties.Remove('Handle')
        $script:Mock.Process | Add-Member -MemberType ScriptProperty -Name Handle -Value { throw 'fixture handle denied' }
    } $true 0
    Check-Case 'failed stop' { $script:Mock.StopError = $true } $true 1
    Check-Case 'exit timeout' { $script:Mock.Exits = $false } $true 1
}
Write-Host "Windows lifecycle function tests passed: $script:Assertions"
