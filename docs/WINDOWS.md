# Windows 11 alpha guide

QuietWard `v0.4.0-alpha.2` is qualified on Windows 11 as an experimental, observation-only monitor. It collects and explains local security evidence but does not automatically change the computer.

## Monitored sources

- running processes, using stable identities and hashed command lines;
- TCP listening sockets;
- optional established outbound connections;
- Run and RunOnce entries;
- enabled scheduled tasks;
- automatic Windows services;
- optional failed-logon evidence when the current account can read the Security log;
- Docker Desktop containers when Docker is available;
- configured sensitive files, including the hosts file by default;
- QuietWard installed source, configuration, database and evidence integrity;
- read-only Microsoft Defender status.

Defender status is labeled separately from QuietWard findings. QuietWard does not start Defender scans or change Defender configuration.

## Install

Requirements: Windows 11, PowerShell and Python 3.11 or newer.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_windows.ps1
```

Optional failed-logon collection:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_windows.ps1 -EnableSecurityLog
```

The installer creates a private user-scoped environment under `%LOCALAPPDATA%\QuietWard`, configuration under `%USERPROFILE%\.config\quietward`, one limited startup task named `QuietWard`, and one **QuietWard Dashboard** shortcut. It performs an initial observation cycle and preserves existing identity/evidence state during upgrades.

## Everyday use

Open **QuietWard Dashboard** from the desktop or visit `http://127.0.0.1:8765/`.

The dashboard shows current health, severity counts, explanations, supporting evidence, collector warnings, Microsoft Defender status, database/evidence-chain status and confirmation that executed actions remain zero.

Finding review remains explicit and auditable through the CLI:

```powershell
quietward incident list --pretty
quietward incident acknowledge FINDING_ID --note "Investigating" --pretty
quietward incident expected FINDING_ID --note "Known approved service" --pretty
quietward incident resolve FINDING_ID --note "Reviewed" --pretty
```

## Diagnose and qualify

```powershell
quietward diagnose --pretty
quietward open-dashboard --pretty
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\qualify_windows.ps1
```

Qualification checks the platform adapter, startup task, dashboard, database, privacy identity, signed evidence, collectors and zero-action invariants without remediating the host.

## Upgrade

Extract the newer release and run `scripts\install_windows.ps1` again. The qualified path preserves the database, privacy identity, evidence-signing key, startup task identity and dashboard shortcut.

## Uninstall

Preserve configuration, keys and evidence:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\uninstall_windows.ps1
```

Remove runtime data too:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\uninstall_windows.ps1 -RemoveData
```

Remove runtime data and configuration intentionally:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\uninstall_windows.ps1 -RemoveData -RemoveConfiguration
```

## Known limitations

- Windows 10 is not independently qualified.
- The alpha runs as the signed-in user rather than a machine-wide privileged service.
- Security-log access depends on local permissions and is disabled by default.
- Docker Desktop remains optional.
- Outbound connection monitoring is opt-in.
- Remediation proposals are non-executable.

## Safety

QuietWard does not disable Defender, Firewall, SmartScreen or Windows Update. It does not expose the dashboard outside loopback, upload telemetry, invoke arbitrary scripts, quarantine files, terminate processes or modify the firewall.
