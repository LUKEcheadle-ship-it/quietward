from __future__ import annotations

from .windows_commands import POWERSHELL_PREFIX


# FAST observation is deliberately limited to fresh process and listening-socket
# evidence. Defender/account enrichment and persistence refresh on STANDARD. This
# keeps the 60-second lane security-fresh without paying for expensive Defender
# cmdlets or a second process inventory on every cycle.
FAST_CORE_SCRIPT = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)

$processes=@()
$processesOk=$false
try {
  $processes=@(
    Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine -ErrorAction Stop | ForEach-Object {
      [pscustomobject]@{
        ProcessId=$_.ProcessId
        ParentProcessId=$_.ParentProcessId
        Name=$_.Name
        ExecutablePath=$_.ExecutablePath
        CommandLine=$_.CommandLine
        UserName=''
      }
    }
  )
  $processesOk=$true
} catch {
  $processes=@()
}

$sockets=@()
$socketsOk=$false
$names=@{}
try {
  foreach ($process in $processes) {
    $name=[System.IO.Path]::GetFileNameWithoutExtension([string]$process.Name)
    $names[[int]$process.ProcessId]=$name
  }
  $sockets=@(
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
  $socketsOk=$true
} catch {
  $sockets=@()
}

[pscustomobject]@{
  DefenderOk=$false
  Defender=$null
  ProcessesOk=$processesOk
  Processes=$processes
  SocketsOk=$socketsOk
  Sockets=$sockets
  PersistenceOk=$false
  Persistence=@()
} | ConvertTo-Json -Compress -Depth 8
""".strip()

WINDOWS_FAST_CORE_COMMAND = (*POWERSHELL_PREFIX, FAST_CORE_SCRIPT)
