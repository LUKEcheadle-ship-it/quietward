# QuietWard

QuietWard is an offline-first, observation-only cybersecurity monitor that explains suspicious host activity without silently changing the computer.

## Release status

`v0.5.0-alpha.1` is the current **experimental alpha release candidate** on `release/v0.5.0-alpha.1`. It is the project's largest architecture, performance, privacy, incident-lifecycle, and detection update so far.

The release candidate must complete exact-public-SHA platform/release qualification before tag/publication.

Intended qualified platforms:

- **Windows 11**
- **Debian 12**

Windows 10, macOS, and other Linux distributions have not completed independent v0.5 qualification. QuietWard is not a replacement for Microsoft Defender, enterprise EDR/MDR, or professional incident response.

## What it does

QuietWard monitors processes, listening ports, persistence, selected sensitive files, authentication evidence, containers when available, Microsoft Defender context on Windows, and its own integrity. It correlates normalized changes into findings, tracks incident lifecycle over time, stores bounded local signed evidence, and presents the result in a read-only local dashboard.

## What v0.5 adds

- **Lower-overhead monitoring:** FAST, STANDARD, DEEP, and MAINTENANCE observation cadences stagger expensive work and keep the normal quiet path lightweight.
- **Native Windows FAST path:** read-only Windows APIs provide fresh process/PID and listener inventory without launching PowerShell on normal quiet FAST cycles; the fixed allowlisted PowerShell path remains a fail-closed fallback/deeper-context path.
- **Stable incident lifecycle:** findings are tracked as `new`, `recurring`, `changed`, and `resolved`, with source-aware resolution so skipped/not-due domains cannot create false absence.
- **Cross-signal context:** bounded same-actor and multi-cycle context strengthens related evidence while guarding against PID reuse and generic-runtime over-correlation.
- **Multi-stage detection:** bounded same-host cross-subject attack-chain correlation and process/network corroboration add context without authorizing host actions.
- **Stronger deterministic behavior signals:** credential spray/dumping, reverse-shell behavior, process injection markers, Office/PDF-to-risky-interpreter ancestry, Linux web/server-to-suspicious-shell ancestry, ransomware recovery inhibition, event-log clearing, and dangerous container configurations.
- **Stronger privacy:** authentication source addresses and optional outbound destinations use installation-keyed HMAC-SHA256 pseudonyms; corrected identity-bearing paths fail closed if the privacy key is unavailable.
- **Safer suppression:** ordinary expected/suppressed noise remains reviewable, while explicit high-signal behavior bypasses ordinary suppression and contextual suppression fails closed when source-cycle evidence is unavailable.
- **Lower-write persistence:** quiet healthy cycles reduce redundant writes inside bounded durability windows while security-bearing/degraded cycles remain immediately durable.
- **Evidence efficiency:** incremental evidence verification is used between mandatory full retained-chain audits, with authoritative full fallback on mismatch.
- **Verified warm restart:** recent established healthy signed state can stage heavier revalidation while FAST observation resumes immediately; unsafe/stale state cold-starts instead.
- **Performance visibility:** CPU, RSS, phase latency, command count/time, persistence mode, and health-write mode are exposed to the local health/dashboard surfaces.
- **Improved dashboard/supportability:** active incidents, lifecycle, monitoring coverage, evidence integrity, retention pressure, Defender/collector context, and explicit zero-action state are visible locally.
- **Redacted incident export v2** and deterministic offline SPDX SBOM tooling.

See `docs/releases/v0.5.0-alpha.1.md`, `docs/V05_REVIEW_GUIDE.md`, and `docs/V05_MARKETING_KIT.md`.

## Safety boundary

QuietWard remains observation-only. It does not automatically quarantine or delete files, terminate processes or services, change firewall rules, isolate a host, execute arbitrary commands, upload telemetry, or perform automatic remediation.

QuietWard does not quarantine/delete files. This explicit release-contract wording is retained for automated safety verification.

Release invariants:

```text
actions_executed == 0
executable_proposals == 0
cloud_upload == false
public_listener == false
```

The dashboard remains read-only and loopback-only by default. Models may explain or reprioritize bounded evidence but cannot authorize an action.

## Privacy

Corrected v0.5 identity-bearing authentication and optional outbound network paths use installation-keyed HMAC-SHA256 pseudonyms. Raw authentication usernames and source/destination IP addresses are not persisted on these paths. Raw process command lines and full scanner output are not retained as durable finding evidence.

See `docs/PRIVACY.md`.

## Windows quick start

Requirements:

- Windows 11
- Python 3.11 or newer
- PowerShell

After release approval, extract the verified source archive and run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_windows.ps1
```

Open the dashboard at `http://127.0.0.1:8765/` or run:

```powershell
quietward status --pretty
quietward open-dashboard --pretty
quietward diagnose --pretty
```

## Debian quick start

```bash
./scripts/install_user_service.sh
quietward status --config ~/.config/quietward/config.json --pretty
```

## Release validation

From the exact release checkout, run the complete migrated/public release gate:

```bash
python scripts/validate_migrated_release.py --pretty
```

The gate runs the complete repository test suite, Python compilation, static observation-only safety audit, strict public-release audit, deterministic double release-bundle build, and independent archive verification.

The dedicated v0.5 detection gate remains available as an additional focused check:

```bash
python scripts/verify_v05_detection.py
```

The Windows release builder does **not** permit a skip-tests release candidate. It freezes the current HEAD, validates the release, performs deterministic double builds, verifies the final archive, and emits a SHA-256 checksum sidecar.

Native Windows 11 and Debian 12 qualification must still pass on the exact public release SHA before the tag is published.

## Export a redacted incident

```bash
quietward export FINDING_ID incident.json --format json --pretty
quietward export FINDING_ID incident.md --format markdown
```

Exports remain local and exclude analyst notes and raw sensitive identities according to the redaction contract.

## Documentation

Start with:

- `docs/FIRST_RUN.md`
- `docs/WINDOWS.md`
- `docs/releases/v0.5.0-alpha.1.md`
- `docs/RELEASE_CHECKLIST.md`
- `docs/V05_REVIEW_GUIDE.md`
- `docs/V05_DETECTION_REGRESSION_MATRIX.md`
- `docs/V05_MARKETING_KIT.md`
- `docs/PRIVACY.md`
- `docs/SECURITY_MODEL.md`
- `docs/EVIDENCE_INTEGRITY.md`

## License

MIT. See `LICENSE`.

## Repository policy

Never commit malware samples, private host logs, credentials, runtime databases, scanner databases, private network inventories, raw persistence files, signing keys or production model inputs. Public issues must not contain private logs, keys, database files, or personal information.
