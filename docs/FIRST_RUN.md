# First run guide

QuietWard is an observation-only monitor. It reports and explains changes; it does not automatically repair, quarantine, delete, block, or stop anything.

## Windows 11 installation

1. Install Python 3.11 or newer.
2. Extract the QuietWard release archive.
3. Open PowerShell in the extracted folder.
4. Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_windows.ps1
```

The execution-policy bypass applies only to that PowerShell process. The installer creates a user-scoped virtual environment, private keys and state, one limited startup task, and a dashboard shortcut.

The installer does not disable Defender, Firewall, SmartScreen, or Windows Update. It does not enable cloud telemetry or a public listener.

## Open the dashboard

Use the desktop shortcut, visit `http://127.0.0.1:8765/`, or run:

```powershell
quietward open-dashboard --pretty
```

The dashboard is available only on the local computer by default.

## Understand the overview

- **Healthy** means the last observation cycle completed and the database/evidence checks are valid.
- **Needs attention** means one or more findings or collector problems should be reviewed. It does not automatically mean malware is present.
- **Collector warning** means an optional source is unavailable or permission-limited. For example, Docker may not be installed or the Security log may be unavailable to the current user.
- **Microsoft Defender evidence** is status reported by Defender. It is not a separate QuietWard malware verdict.

## Understand a finding

Open a finding to see:

- severity and score;
- a plain-language explanation;
- reasons that affected the score;
- supporting events;
- current review state;
- a suggested response or non-executable remediation plan.

A high severity can represent a real but authorized exposure, such as a deliberately enabled file-sharing service. Review the evidence before changing the computer.

## Run diagnostics

```powershell
quietward diagnose --pretty
```

Diagnostics check the platform, configuration, local database, evidence chain, collector prerequisites, and safety invariants. They do not modify the host.

Run the bounded Windows qualification with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\qualify_windows.ps1
```

## Common messages

### Python 3.11 or newer is required

Install a current Python release and rerun the installer. A user-scoped Python 3.12 installation is recommended.

### Docker inventory unavailable

Docker Desktop is optional. This warning can be ignored when Docker is not used.

### Security-log collection unavailable

Failed-logon collection requires permission to read the Windows Security log. It is disabled by default and the rest of QuietWard remains usable.

### Dashboard is not responding

Run:

```powershell
quietward diagnose --pretty
Get-ScheduledTask -TaskName "QuietWard" -ErrorAction SilentlyContinue
```

Then rerun the installer to perform a safe in-place repair. Existing data and identity keys are preserved.

### Evidence signing key is required

Do not delete or replace the key after signed evidence exists. Restore the original private key or preserve the database for incident review and start a deliberate fresh state.

## Upgrade

Extract the newer release and run `scripts\install_windows.ps1` again. The qualified upgrade path preserves the database, privacy identity, evidence-signing key, one startup task, and one dashboard shortcut.

## Uninstall

Conservative uninstall:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\uninstall_windows.ps1
```

This removes the startup task and installed runtime while preserving configuration, database, and private keys. Use explicit deletion switches only when you intentionally want to remove QuietWard-owned state.

## Privacy

QuietWard is offline-first. Raw process arguments, account names, remote addresses, and persistence labels are not intended to be persisted. Identity-bearing values use installation-specific keyed pseudonymous identifiers. Keep incident exports and runtime state private unless you have reviewed them.

## Getting help

Include the sanitized output from `quietward diagnose --pretty`, the QuietWard version, and the operating system version. Never post private keys, the runtime database, raw host logs, or unreviewed qualification reports.
