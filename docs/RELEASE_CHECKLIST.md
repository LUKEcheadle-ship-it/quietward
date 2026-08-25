# QuietWard v0.5.0-alpha.1 release checklist

Candidate branch: `release/v0.5.0-alpha.1`

Package version: `0.5.0a1`

This checklist is for the **combined public v0.5 release candidate**: the approved lower-overhead performance/lifecycle core plus the public detection/privacy hardening line. Prior v0.4 qualification and the approved private v0.5 source evidence are baseline evidence, but neither substitutes for the exact-public-SHA release gates below.

Do not mark QuietWard stable or production-ready. v0.5.0-alpha.1 remains an **experimental alpha**.

## Exact public candidate record

- [ ] Record the final public candidate SHA after all release-tree corrections are complete.
- [ ] Confirm the tracked working tree is clean at that SHA.
- [ ] Confirm `pyproject.toml` and `quietward.__version__` both report `0.5.0a1`.
- [ ] Confirm README, CHANGELOG, release notes, reviewer guide, privacy doc, marketing kit and release checklist describe the same combined candidate.
- [ ] Confirm PR #4 targets `main` from `release/v0.5.0-alpha.1` and remains mergeable.

## Complete public release gate

Install release-test dependencies without adding runtime dependencies:

```text
python -m pip install -e ".[release]"
```

Then run:

```text
python scripts/validate_migrated_release.py --pretty
```

This exact SHA must pass:

- [ ] complete unittest-based core suite;
- [ ] complete pytest-based detection-hardening suite with warnings treated as errors;
- [ ] source/tests/scripts Python compilation;
- [ ] combined v0.5 source/document contract;
- [ ] static observation-only safety audit;
- [ ] strict public-release audit with zero blockers;
- [ ] deterministic double release-bundle build;
- [ ] independent verification of both release archives;
- [ ] no private approval/development files, runtime databases, logs, keys or GitHub Actions workflows.

Any failure blocks release.

## Core architecture / performance contract

Confirm the exact public candidate retains:

- [ ] FAST / STANDARD / DEEP / MAINTENANCE cadence separation;
- [ ] native read-only Windows FAST process/PID inventory;
- [ ] native read-only Windows FAST listening-socket inventory;
- [ ] PowerShell only as fixed fail-closed fallback/deeper context, not the normal quiet FAST path;
- [ ] stable `new`, `recurring`, `changed`, `resolved` incident lifecycle;
- [ ] source-aware resolution so not-due/degraded domains cannot count as observed absence;
- [ ] bounded same-actor and prior-cycle temporal context;
- [ ] bounded multi-stage same-host attack-chain and process/network correlation;
- [ ] lower-write quiet persistence with durable security-bearing/degraded cycles;
- [ ] incremental evidence verification with mandatory authoritative full checks;
- [ ] verified warm-start fallback behavior;
- [ ] bounded adaptive deferral limited to optional DEEP/MAINTENANCE work;
- [ ] CPU/RSS/per-phase/external-command performance telemetry;
- [ ] lifecycle/coverage/evidence/retention/performance state visible through read-only local status/dashboard surfaces.

Performance targets for the native Windows persistent service:

- [ ] mean FAST CPU <= 2% total CPU capacity;
- [ ] max RSS <= 100 MiB excluding external scanners/models;
- [ ] FAST p50 <= 500 ms;
- [ ] FAST p95 <= 1500 ms;
- [ ] analysis p95 <= 50 ms;
- [ ] at least five real FAST-only samples.

## Detection / privacy gate

The complete gate and `python scripts/verify_v05_detection.py` must confirm:

- [ ] cross-subject same-host attack-chain tests;
- [ ] process/network corroboration tests;
- [ ] privacy-preserving credential-spray tests;
- [ ] installation-keyed Linux/Windows authentication source-address privacy;
- [ ] installation-keyed Linux/Windows optional outbound-destination privacy;
- [ ] same raw address produces different durable identities under different installation keys;
- [ ] connection/auth paths fail closed if the privacy identity is unavailable;
- [ ] high-signal suppression bypass for reverse shell/credential spray and benign lower-signal controls;
- [ ] fail-closed contextual suppression when authoritative source-cycle evidence is unavailable;
- [ ] Windows process regex/recovery/evasion parser behavior;
- [ ] Windows outbound collector/parser signature and bounds;
- [ ] Windows failed-logon keyed source/account contract;
- [ ] Windows persistence `Category/Name/Command/State/Account` privacy contract plus keyed `command_hash` compatibility alias;
- [ ] high-confidence behavior scoring regressions;
- [ ] Windows document/PDF→interpreter ancestry tests and negative controls;
- [ ] Windows recovery-inhibition/event-log-clearing tests and negative controls;
- [ ] Linux reverse-shell/downloader/encoded-shell tests;
- [ ] Linux web/server→already-suspicious-shell ancestry tests and negative controls;
- [ ] adversarial/false-positive detection matrix tests.

## Windows 11 exact-SHA qualification

On a fresh checkout of the exact public candidate SHA:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_release_candidate.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\qualify_windows.ps1
```

Required:

- [ ] builder refuses `-SkipTests` and freezes/rechecks exact HEAD;
- [ ] complete public release gate passes from the Windows builder;
- [ ] deterministic two-build archive hashes match;
- [ ] final archive and SHA-256 checksum sidecar verify independently;
- [ ] Windows qualification passes on Windows 11;
- [ ] install/upgrade/uninstall-reinstall remains user-scoped and rollback-safe;
- [ ] startup task remains current-user/limited-run-level;
- [ ] dashboard remains loopback-only by default and read-only;
- [ ] doctor/diagnose/status and SQLite/evidence checks are healthy;
- [ ] evidence chain/signatures verify;
- [ ] Defender integration remains read-only;
- [ ] native FAST process/listener path works on the public SHA;
- [ ] optional connection/auth/persistence paths retain keyed privacy boundaries;
- [ ] no raw process command line, auth IP/username or sensitive persistence command/account value is durably persisted by corrected paths;
- [ ] high-signal evidence remains visible despite older routine suppression;
- [ ] production QuietWard database, health, alert log, service lock, evidence-signing key and privacy-identity key are not modified by release qualification except where an explicitly isolated test install is being exercised.

## Debian 12 exact-SHA qualification

On the exact public candidate SHA:

```text
./scripts/validate_release.sh
```

Also confirm:

- [ ] Debian 12 service/install path remains observation-only;
- [ ] doctor/diagnose/status and local database/evidence verification pass;
- [ ] SSH credential-spray collection preserves installation-keyed source/user pseudonymization;
- [ ] optional outbound destinations use installation-keyed identity and raw addresses remain absent;
- [ ] Linux parent/child behavioral markers operate without persisting raw arguments;
- [ ] high-signal suppression bypass works without making lower-specificity administrative context unsuppressible;
- [ ] optional Docker/connection collectors fail as warnings when unavailable rather than confirmed threats;
- [ ] batched Docker inspection path remains bounded and fail-closed;
- [ ] reboot/service recovery remains healthy.

## Safety gates

The exact public SHA must preserve:

- [ ] `actions_executed == 0`;
- [ ] `executable_proposals == 0`;
- [ ] dashboard bind is `127.0.0.1` by default;
- [ ] cloud upload is disabled;
- [ ] public listener is disabled by default;
- [ ] automatic remediation is disabled;
- [ ] no file quarantine/deletion path exists;
- [ ] no process/service termination path exists;
- [ ] no firewall/host-isolation path exists;
- [ ] no arbitrary command execution path exists;
- [ ] native Windows FAST collector contains no mutation primitives;
- [ ] no GitHub Actions workflows are present or used.

## Deterministic release package / SBOM

Required package evidence:

- [ ] final archive name is `quietward-v0.5.0-alpha.1-source.zip`;
- [ ] release candidate built twice with identical SHA-256;
- [ ] checksum sidecar exactly matches the final archive;
- [ ] `scripts/verify_release_bundle.py` returns PASS;
- [ ] archive manifest matches every packaged file/hash/size;
- [ ] archive contains the v0.5 release notes, review guide, marketing kit, safety gate, public gate and SBOM tooling;
- [ ] deterministic SPDX 2.3 SBOM can be generated offline from the exact source tree and exact commit SHA;
- [ ] archive contains no runtime databases, logs, keys, host evidence, scanner databases, qualification output or private machine evidence.

## Supported-platform statement

Only after the exact-public-SHA platform reruns pass:

- [ ] Windows 11 may be listed as qualified for the experimental alpha;
- [ ] Debian 12 may be listed as qualified for the experimental alpha;
- [ ] Windows 10 remains not independently qualified;
- [ ] macOS remains not independently qualified;
- [ ] other Linux distributions remain experimental/not advertised as supported.

## Repository / marketing review

- [ ] MIT license, SECURITY, support/contribution/code-of-conduct/privacy documentation and changelog remain present;
- [ ] final public diff reviewed for secrets, private host data and machine-specific evidence;
- [ ] old detection-only PR #3 remains closed as superseded by PR #4;
- [ ] marketing uses `docs/V05_MARKETING_KIT.md` and keeps **experimental alpha** language;
- [ ] no claim of enterprise EDR replacement, breach prevention, autonomous remediation, production-readiness or zero false positives;
- [ ] publish verified source archive plus SHA-256 sidecar; publish SBOM if desired;
- [ ] keep host-specific qualification evidence/runtime state private.

## Publication gate

Only after every required item above records PASS on the **same exact public SHA**:

- [ ] mark PR #4 ready for review;
- [ ] merge PR #4 into `main` with explicit owner authorization;
- [ ] create tag `v0.5.0-alpha.1` from the resulting approved release commit;
- [ ] publish the verified deterministic source archive and checksum sidecar as a GitHub prerelease;
- [ ] publish the v0.5 limitations and observation-only safety language;
- [ ] begin marketing using `docs/V05_MARKETING_KIT.md`.

Any unchecked required exact-SHA qualification item blocks publication.
