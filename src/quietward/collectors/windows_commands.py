from __future__ import annotations

POWERSHELL_PREFIX = (
    "powershell.exe",
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-Command",
)

PROCESS_SCRIPT = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$rows=@()
$owners=@{}
try {
  Get-Process -IncludeUserName -ErrorAction Stop | ForEach-Object {
    $owners[[int]$_.Id]=[string]$_.UserName
  }
} catch {$owners=@{}}
Get-CimInstance Win32_Process | ForEach-Object {
  $rows += [pscustomobject]@{
    ProcessId=$_.ProcessId
    ParentProcessId=$_.ParentProcessId
    Name=$_.Name
    ExecutablePath=$_.ExecutablePath
    CommandLine=$_.CommandLine
    UserName=$owners[[int]$_.ProcessId]
  }
}
$rows | ConvertTo-Json -Compress -Depth 4
""".strip()

DEFENDER_SCRIPT = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$status=Get-MpComputerStatus -ErrorAction Stop
[pscustomobject]@{
  AntivirusEnabled=$status.AntivirusEnabled
  RealTimeProtectionEnabled=$status.RealTimeProtectionEnabled
  AntivirusSignatureVersion=$status.AntivirusSignatureVersion
  AntivirusSignatureAge=$status.AntivirusSignatureAge
  QuickScanEndTime=$status.QuickScanEndTime
  ActiveThreatCount=@(Get-MpThreat -ErrorAction SilentlyContinue).Count
  RemediationRequired=(@(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.ActionSuccess -eq $false }).Count -gt 0)
} | ConvertTo-Json -Compress -Depth 3
""".strip()

SOCKET_SCRIPT = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$names=@{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object {$names[[int]$_.Id]=$_.ProcessName}
$rows=@(
  Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
      Protocol='tcp'
      LocalAddress=$_.LocalAddress
      LocalPort=$_.LocalPort
      OwningProcess=$_.OwningProcess
      ProcessName=$names[[int]$_.OwningProcess]
    }
  }
)
$rows | ConvertTo-Json -Compress -Depth 4
""".strip()

CONNECTION_SCRIPT = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$names=@{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object {$names[[int]$_.Id]=$_.ProcessName}
$rows=@(
  Get-NetTCPConnection -State Established -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
      Protocol='tcp'
      RemoteAddress=$_.RemoteAddress
      RemotePort=$_.RemotePort
      ProcessName=$names[[int]$_.OwningProcess]
    }
  }
)
$rows | ConvertTo-Json -Compress -Depth 4
""".strip()

PERSISTENCE_SCRIPT = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$rows=@()
$runKeys=@(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($key in $runKeys) {
  if (Test-Path $key) {
    $item=Get-ItemProperty -Path $key
    foreach ($property in $item.PSObject.Properties) {
      if ($property.Name -notmatch '^PS') {
        $rows += [pscustomobject]@{Category='registry_run';Name=('{0}\{1}' -f $key,$property.Name);Command=[string]$property.Value;State='enabled';Account=''}
      }
    }
  }
}
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
  $task=$_
  $commands=@($task.Actions | ForEach-Object {('{0} {1}' -f [string]$_.Execute,[string]$_.Arguments).Trim()})
  $rows += [pscustomobject]@{Category='scheduled_task';Name=('{0}{1}' -f $task.TaskPath,$task.TaskName);Command=($commands -join ' | ');State=[string]$task.State;Account=[string]$task.Principal.UserId}
}
Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' } | ForEach-Object {
  $rows += [pscustomobject]@{Category='service_auto';Name=$_.Name;Command=$_.PathName;State='enabled';Account=$_.StartName}
}
$rows | ConvertTo-Json -Compress -Depth 4
""".strip()

CORE_SCRIPT = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$defender=$null;$defenderOk=$false
try {$status=Get-MpComputerStatus -ErrorAction Stop;$defender=[pscustomobject]@{AntivirusEnabled=$status.AntivirusEnabled;RealTimeProtectionEnabled=$status.RealTimeProtectionEnabled;AntivirusSignatureVersion=$status.AntivirusSignatureVersion;AntivirusSignatureAge=$status.AntivirusSignatureAge;QuickScanEndTime=$status.QuickScanEndTime;ActiveThreatCount=@(Get-MpThreat -ErrorAction SilentlyContinue).Count;RemediationRequired=(@(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.ActionSuccess -eq $false }).Count -gt 0)};$defenderOk=$true}catch{}
$processes=@();$processesOk=$false;$owners=@{}
try {Get-Process -IncludeUserName -ErrorAction Stop | ForEach-Object {$owners[[int]$_.Id]=[string]$_.UserName}} catch {$owners=@{}}
try {$processes=@(Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {[pscustomobject]@{ProcessId=$_.ProcessId;ParentProcessId=$_.ParentProcessId;Name=$_.Name;ExecutablePath=$_.ExecutablePath;CommandLine=$_.CommandLine;UserName=$owners[[int]$_.ProcessId]}});$processesOk=$true}catch{$processes=@()}
$sockets=@();$socketsOk=$false;$names=@{}
try {Get-Process -ErrorAction SilentlyContinue | ForEach-Object {$names[[int]$_.Id]=$_.ProcessName};$sockets=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {[pscustomobject]@{Protocol='tcp';LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;OwningProcess=$_.OwningProcess;ProcessName=$names[[int]$_.OwningProcess]}});$socketsOk=$true}catch{$sockets=@()}
$persistence=@();$persistenceOk=$false
try {
  $runKeys=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce')
  foreach ($key in $runKeys) {if (Test-Path $key) {$item=Get-ItemProperty -Path $key -ErrorAction Stop;foreach ($property in $item.PSObject.Properties) {if ($property.Name -notmatch '^PS') {$persistence += [pscustomobject]@{Category='registry_run';Name=('{0}\{1}' -f $key,$property.Name);Command=[string]$property.Value;State='enabled';Account=''}}}}}
  Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {$task=$_;$commands=@($task.Actions | ForEach-Object {('{0} {1}' -f [string]$_.Execute,[string]$_.Arguments).Trim()});$persistence += [pscustomobject]@{Category='scheduled_task';Name=('{0}{1}' -f $task.TaskPath,$task.TaskName);Command=($commands -join ' | ');State=[string]$task.State;Account=[string]$task.Principal.UserId}}
  Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.StartMode -eq 'Auto' } | ForEach-Object {$persistence += [pscustomobject]@{Category='service_auto';Name=$_.Name;Command=$_.PathName;State='enabled';Account=$_.StartName}}
  $persistenceOk=$true
} catch {$persistence=@()}
[pscustomobject]@{DefenderOk=$defenderOk;Defender=$defender;ProcessesOk=$processesOk;Processes=$processes;SocketsOk=$socketsOk;Sockets=$sockets;PersistenceOk=$persistenceOk;Persistence=$persistence} | ConvertTo-Json -Compress -Depth 8
""".strip()

AUTH_SCRIPT = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$start=(Get-Date).AddMinutes(-15)
$rows=@(
  Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$start} -ErrorAction Stop | ForEach-Object {
    [xml]$eventXml=$_.ToXml();$data=@{}
    foreach ($node in $eventXml.Event.EventData.Data) {$data[[string]$node.Name]=[string]$node.'#text'}
    [pscustomobject]@{TimeCreated=$_.TimeCreated.ToUniversalTime().ToString('o');User=$data['TargetUserName'];SourceAddress=$data['IpAddress'];Status=$data['Status'];SubStatus=$data['SubStatus']}
  }
)
$rows | ConvertTo-Json -Compress -Depth 4
""".strip()

WINDOWS_PROCESS_COMMAND = (*POWERSHELL_PREFIX, PROCESS_SCRIPT)
WINDOWS_SOCKET_COMMAND = (*POWERSHELL_PREFIX, SOCKET_SCRIPT)
WINDOWS_CONNECTION_COMMAND = (*POWERSHELL_PREFIX, CONNECTION_SCRIPT)
WINDOWS_PERSISTENCE_COMMAND = (*POWERSHELL_PREFIX, PERSISTENCE_SCRIPT)
WINDOWS_AUTH_COMMAND = (*POWERSHELL_PREFIX, AUTH_SCRIPT)
WINDOWS_DEFENDER_COMMAND = (*POWERSHELL_PREFIX, DEFENDER_SCRIPT)
WINDOWS_CORE_COMMAND = (*POWERSHELL_PREFIX, CORE_SCRIPT)

WINDOWS_COMMANDS = {
    WINDOWS_PROCESS_COMMAND,
    WINDOWS_SOCKET_COMMAND,
    WINDOWS_CONNECTION_COMMAND,
    WINDOWS_PERSISTENCE_COMMAND,
    WINDOWS_AUTH_COMMAND,
    WINDOWS_DEFENDER_COMMAND,
    WINDOWS_CORE_COMMAND,
}
