# Changelog

## 0.5.0-alpha.1 - 2026-08-25

QuietWard v0.5 is the project's largest update so far, combining the lower-overhead always-on core, stable incident lifecycle, stronger privacy/evidence handling, and the public detection-hardening line while preserving observation-only behavior.

### Added

- FAST, STANDARD, DEEP, and MAINTENANCE observation cadences with staggered heavy work and bounded adaptive deferral for optional deep/maintenance work only.
- Native read-only Windows FAST process/PID and listening-socket inventory that avoids PowerShell startup on the normal quiet path while retaining fixed allowlisted PowerShell fallback/deeper context.
- Stable incident lifecycle states: `new`, `recurring`, `changed`, and `resolved`.
- Source-aware lifecycle resolution so degraded/not-due domains cannot be treated as proof of absence.
- Bounded same-actor and prior-cycle temporal context with PID-reuse safeguards.
- Bounded 15-minute same-host cross-subject attack-chain correlation for corroborated multi-stage activity.
- Process/network corroboration using bounded existing process metadata and privacy-preserving destination identity.
- Privacy-preserving credential-spray aggregation on Windows and Debian without persisting raw source addresses or usernames.
- Installation-keyed HMAC-SHA256 identities for corrected authentication and optional outbound-address paths.
- High-confidence deterministic scoring for reverse shells, credential dumping, process injection, document-spawned interpreters, ransomware recovery inhibition, event-log clearing, and dangerous container configurations.
- Windows document/PDF application to interpreter/LOLBin parent-child detection with benign negative controls.
- Linux web/server to already-suspicious shell ancestry enrichment without persisting raw command arguments.
- High-signal suppression bypass and fail-closed contextual suppression behavior.
- Lower-write quiet persistence with bounded durable checkpoints and periodic full snapshots.
- Incremental evidence verification between mandatory full retained-chain audits, with authoritative full fallback on mismatch.
- Verified staged warm restart from recent established healthy signed state.
- Runtime CPU, RSS, per-phase latency, command-count/time, persistence-mode, and health-write telemetry.
- Enhanced read-only dashboard/status surfaces for lifecycle, monitoring coverage, evidence integrity, retention pressure, and explicit zero-action state.
- Redacted incident export v2 and deterministic offline SPDX SBOM tooling.
- Dedicated v0.5 adversarial, false-positive, process/network, parent-child, release-contract, integration, and detection-matrix regression suites.

### Hardened

- Large multi-account credential sprays reach a HIGH priority floor only after strong source/account corroboration.
- High-signal behavioral floors affect review priority only and never authorize a host action.
- Cross-subject chains require bounded same-host temporal/phase corroboration rather than unrelated event diversity.
- Expected/suppressed routine activity cannot hide later explicit high-signal behavior.
- Windows command/scanner execution resolves trusted absolute executables, rejects link/reparse paths, uses fixed allowlists, sanitized environments, and `shell=False`.
- Quiet cycles can avoid redundant persistence/evidence/health durability work, while security-bearing or degraded observations remain durable.
- Evidence and freshness caches are bounded, invalidatable, and periodically return to authoritative checks.
- Dashboard remains read-only and loopback-only by default; cloud upload/public listeners remain disabled.
- Release verification enforces `actions_executed == 0`, `executable_proposals == 0`, no GitHub Actions workflows, and the observation-only safety boundary.

### Release qualification

Run the complete public release gate:

```text
python scripts/validate_migrated_release.py --pretty
```

The focused v0.5 detection gate remains available:

```text
python scripts/verify_v05_detection.py
```

Then build the deterministic Windows release archive with:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_release_candidate.ps1
```

The release gate requires complete repository tests, compilation, static safety audit, strict public-release audit, deterministic double-build SHA match, checksum sidecar generation, and independent archive verification. Native Windows 11 and Debian 12 qualification still must pass on the exact public release SHA before tag/publication.

## 0.4.0-alpha.2 - 2026-08-17

- Group dashboard findings by normalized title, subject category, and detector family while preserving every original record and incident link.
- Sort critical through informational findings deterministically, with unknown severities last and urgent review states first.
- Move first-run guidance above findings with a local-only dismiss/restore control.
- Format dashboard timestamps for people while retaining exact UTC values.
- Translate allowlisted scoring reasons into plain language and retain escaped raw details.
- Make manual and automatic refreshes observable, non-overlapping, and non-destructive on failure.
- Correct the installed runtime version metadata to `0.4.0a2` and enforce consistency with project metadata in the release test suite.
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
