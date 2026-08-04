# QuietWard operations

## Commands

```bash
quietward doctor --config ~/.config/quietward/config.json --pretty
quietward status --config ~/.config/quietward/config.json --pretty
quietward scan --config ~/.config/quietward/config.json --scanner clamav --pretty
systemctl --user status quietward.service
journalctl --user -u quietward.service
```

## State

By default, QuietWard stores its SQLite database, health report, alert JSONL and lock beneath `~/.local/state/quietward`. Files are created with private permissions. Retention is bounded by both age and record counts.

On Windows, the equivalent private runtime lives under `%LOCALAPPDATA%\QuietWard` and starts through one limited current-user scheduled task named `QuietWard`.

## Failure behavior

Collector and scanner failures are recorded as bounded errors. Optional tools do not trigger privilege escalation or package installation. Scanner errors never authorize containment. After the configured consecutive failure limit, the service exits nonzero and the platform service manager may restart it.

## Clean removal

Preserve evidence and configuration on Debian:

```bash
./scripts/uninstall_user_service.sh
```

Delete QuietWard-owned configuration and data as well:

```bash
./scripts/uninstall_user_service.sh --delete-data
```

On Windows, use `scripts\uninstall_windows.ps1`; data and keys are retained unless explicit removal switches are supplied.
