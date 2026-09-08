# First-run troubleshooting

Use this guide when a supported Windows 11 or Debian 12 first-run installation does not become healthy.

Start with the read-only prerequisite check.

### Windows PowerShell

```powershell
quietward doctor --pretty
```

### Debian

```bash
quietward doctor --pretty
```

`quietward doctor` checks the platform, collector selection, required commands, privacy identity, evidence-signing state, enabled scanners, and database integrity. It does not modify the host.

## Troubleshooting matrix

| Symptom                                            | Check                                                                                                                              | Safe next step                                                                                                                                                                                          |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Python version is unsupported                      | Check the Python version reported during installation. QuietWard requires Python 3.11 or newer.                                    | Install a supported Python version, then rerun the existing installer.                                                                                                                                  |
| `quietward doctor` reports an unsupported platform | Run `quietward doctor --pretty` and inspect the `platform` and `collector_selection` checks.                                       | Confirm that the host is Windows 11 or Debian 12 and that the selected collector matches the platform.                                                                                                  |
| Configuration is invalid                           | Run `quietward doctor --pretty`. Configuration parsing errors identify the invalid section or field.                               | Correct the existing configuration using the documented configuration format, then run `quietward doctor --pretty` again.                                                                               |
| Dashboard does not start                           | Check whether the default loopback port is already in use.                                                                         | Confirm the configured dashboard port and retry the existing startup path. Do not expose the dashboard publicly.                                                                                        |
| Dashboard port `8765` is already in use            | **Windows:** `Get-NetTCPConnection -LocalPort 8765 -ErrorAction SilentlyContinue`<br><br>**Debian:** `ss -ltn '( sport = :8765 )'` | Identify the existing listener before changing anything. Keep QuietWard on loopback unless an authenticated private-network configuration is deliberately required.                                     |
| Privacy identity check fails                       | Run `quietward doctor --pretty` and inspect `privacy_identity`.                                                                    | Preserve the existing privacy identity key. Do not replace a valid installation key just to make the check pass.                                                                                        |
| Evidence signing check fails                       | Run `quietward doctor --pretty` and inspect `evidence_signing`.                                                                    | Do not delete or replace a signing key when signed evidence already exists. Preserve the existing key/database pair for review.                                                                         |
| A collector is unavailable                         | Inspect `collector_selection` and the `command:*` checks in `quietward doctor --pretty`.                                           | Treat optional collector warnings as capability limitations. Enable or install only the supported dependency already documented for the host.                                                           |
| Docker inventory is unavailable                    | Inspect the Docker-related check.                                                                                                  | Docker collection is optional. If Docker is not installed or running, the rest of QuietWard can still be used.                                                                                          |
| Windows Security-log collection is unavailable     | Inspect the relevant collector warning from `quietward doctor --pretty`.                                                           | Security-log collection depends on local permissions and is optional. The rest of QuietWard remains usable.                                                                                             |
| Debian service is not running                      | Check the user service with `systemctl --user status quietward.service`.                                                           | If the service was installed using the supported installer, use the existing service/install path rather than creating a new system service.                                                            |
| Health file is missing or stale                    | Check the configured health path. The default is `~/.local/state/quietward/health.json`.                                           | Confirm that the QuietWard service is running, then rerun `quietward doctor --pretty` and inspect service status.                                                                                       |
| Database integrity check fails                     | Run `quietward doctor --pretty` and inspect `database_integrity`.                                                                  | Preserve the database and associated evidence/signing key. Do not delete runtime state as a first troubleshooting step.                                                                                 |
| First run still fails after the checks pass        | Capture only sanitized diagnostic output.                                                                                          | Include `quietward doctor --pretty`, the QuietWard version, and the OS version when asking for help. Never include private keys, runtime databases, raw host logs, or unreviewed qualification reports. |

## Platform-specific service checks

### Windows 11

QuietWard uses a user-scoped startup task and a local loopback dashboard.

Check the startup task:

```powershell
Get-ScheduledTask -TaskName "QuietWard" -ErrorAction SilentlyContinue
```

Then run:

```powershell
quietward doctor --pretty
```

The dashboard is normally available at:

```text
http://127.0.0.1:8765/
```

### Debian 12

Check the user service:

```bash
systemctl --user status quietward.service
```

Then run:

```bash
quietward doctor --pretty
```

The default health file is:

```text
~/.local/state/quietward/health.json
```

## Privacy and safety

Do not post the following in public issues or pull requests:

* private identity or evidence-signing keys;
* the QuietWard runtime database;
* raw host logs;
* raw process arguments or network inventories;
* private qualification reports;
* other machine-specific security evidence.

Troubleshooting should remain within QuietWard's observation-only boundary. Do not add commands that terminate processes, modify firewall rules, change host security settings, upload telemetry, or otherwise grant QuietWard new authority.
