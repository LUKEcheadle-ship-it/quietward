# Changelog

## 0.4.0-alpha.2 - 2026-08-17

- Group dashboard findings by normalized title, subject category, and detector family while preserving every original record and incident link.
- Sort critical through informational findings deterministically, with unknown severities last and urgent review states first.
- Move first-run guidance above findings with a local-only dismiss/restore control.
- Format dashboard timestamps for people while retaining exact UTC values.
- Translate allowlisted scoring reasons into plain language and retain escaped raw details.
- Make manual and automatic refreshes observable, non-overlapping, and non-destructive on failure.
- macOS remains unsupported and not natively qualified; its platform gate is intentionally unchanged.

All notable changes are documented here.

## Unreleased

### Changed

- Renamed the product, repository package, command, installers, services, local paths, dashboard, model assets, and release archives to QuietWard.
- Retained a narrow compatibility namespace for pre-rename alpha Python imports while all new usage targets `quietward`.
- Added a rollback-safe Debian user-install migration that preserves corrected pre-rename privacy identity, signed evidence, database and review state without rewriting historical signatures.
- Made target-host qualification use the installed service configuration and treat expected non-root file permission boundaries as warnings while enforcing event-specific privacy flags.
- Removed the unnecessary standalone NOTICE disclaimer; the standard MIT LICENSE remains authoritative.

## 0.4.0-alpha.1 - 2026-08-01

QuietWard's first cross-platform experimental alpha was originally qualified under its pre-rename working title.

### Added

- Qualified Windows 11 monitoring with a user-scoped offline installer, limited current-user startup task, conservative uninstall, and upgrade preservation.
- Read-only Windows collectors for processes, TCP listeners, optional outbound connections, Run/RunOnce entries, scheduled tasks, automatic services, optional failed-logon evidence, configured file integrity, and Docker Desktop when available.
- Read-only Microsoft Defender status evidence. QuietWard does not start scans or change Defender settings.
- Automatic platform selection, portable process locking, and a capability-tolerant systemd Linux adapter.
- A loopback-only dashboard with plain-language findings, severity and evidence status, supporting events, collector warnings, and explicit observation-only messaging.
- One-command diagnostics, dashboard launching, Windows qualification, deterministic source packaging, and archive verification.
- Review-only remediation plans with approval and rollback metadata; plans remain non-executable.

### Changed

- Windows persistence and process identities are normalized to reduce repeated baseline noise.
- Identity-bearing Windows data uses installation-specific keyed pseudonymous identifiers and fails closed when the privacy key is unavailable.
- Release positioning now lists Windows 11 and Debian 12 as the qualified experimental-alpha platforms.

### Qualification

- Windows 11: installer, upgrade, uninstall/reinstall, dashboard, doctor, SQLite, evidence signatures, privacy checks, compilation, release audit, and 123 tests passed with four platform-appropriate skips.
- Debian 12: corrected alpha path retained its controlled-scenario, privacy, evidence-chain, recovery, and extended real-host qualification.
- Actions executed: 0. Executable proposals: 0. Cloud upload and public listeners: disabled.

### Known limitations

- Windows 10 has not been independently qualified.
- Windows Security-log collection is permission-dependent and disabled by default.
- Docker Desktop was not installed on the Windows qualification host; its absence is treated as an optional warning.
- Other Linux distributions are experimental and are not advertised as supported.
- This alpha is not a replacement for Microsoft Defender or professional endpoint protection.

## 0.3.0-alpha.2.1

- Completed the privacy correction for authentication and process account identities using installation-specific HMAC-SHA256 identifiers.
- Passed 108 focused tests and all 18 controlled qualification scenarios.
- Preserved observation-only operation with zero executed actions.

## 0.3.0-alpha.2

- Authentication usernames changed to installation-specific keyed pseudonymous identifiers and fail closed when the privacy key is unavailable.
- Alpha.1 authentication evidence may contain raw usernames and should remain privately archived.

## 0.3.0-alpha.1

- Initial Debian observation-only technical preview with local collectors, scanner adapters, bounded storage, findings, and signed evidence support.
