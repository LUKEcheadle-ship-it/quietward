# QuietWard v0.5.0-alpha.1 release checklist

Candidate branch: `feature/detection-hardening-v05`

Package version: `0.5.0a1`

This checklist is for the v0.5 detection-hardening release candidate. The prior v0.4 Windows 11/Debian 12 qualification is useful baseline evidence but **does not substitute for rerunning the v0.5 gates on the exact release SHA**.

Do not mark QuietWard stable or production-ready.

Start review with `docs/V05_RELEASE_CORRECTIONS.md`; it records defects found by the full code/function review and the correction controls now required by the release gate.

## Exact candidate record

- [ ] Record the final candidate SHA after qualification-driven corrections are complete.
- [ ] Confirm tracked working tree is clean at that SHA.
- [ ] Confirm `pyproject.toml` and `quietward.__version__` both report `0.5.0a1`.
- [ ] Confirm `CHANGELOG.md`, README, `docs/releases/v0.5.0-alpha.1.md`, reviewer guide, privacy doc and release-correction record describe the same candidate.

## Detection gate

Install release-test dependencies without adding runtime dependencies:

```text
python -m pip install -e ".[release]"
```

Then run:

```text
python scripts/verify_v05_detection.py
```

The exact SHA must pass:

- [ ] full pytest suite with warnings treated as errors;
- [ ] source/tests/scripts compile check;
- [ ] public-release audit with zero blockers;
- [ ] observation-only README/source contract;
- [ ] cross-subject same-host attack-chain tests;
- [ ] process/network corroboration tests;
- [ ] privacy-preserving credential-spray tests;
- [ ] **installation-keyed Linux/Windows authentication source-address privacy tests**;
- [ ] **installation-keyed Linux/Windows optional outbound-destination privacy tests**;
- [ ] same raw address produces different durable identity under different installation keys;
- [ ] connection/auth collection fails closed rather than persisting a weaker public address digest when the privacy identity is unavailable;
- [ ] **high-signal suppression bypass tests** for reverse shell/credential spray and negative lower-signal control;
- [ ] corrected Windows process regex behavior executes without parser exception;
- [ ] corrected Windows outbound-connection collector/parser signature and bounds tests;
- [ ] corrected Windows failed-logon keyed-source/account contract;
- [ ] corrected Windows persistence `Category/Name/Command/State/Account` parser contract and raw-value exclusion;
- [ ] high-confidence behavioral scoring regressions;
- [ ] Windows document→interpreter ancestry tests and negative controls;
- [ ] Windows recovery-inhibition/event-log-clearing tests and negative controls;
- [ ] Linux reverse-shell/downloader/encoded-shell tests;
- [ ] Linux web-server→already-suspicious-shell ancestry tests and negative controls;
- [ ] adversarial/false-positive detection matrix tests.

Any failure blocks release.

## Windows 11 qualification

On the exact candidate SHA/archive:

- [ ] `scripts/build_release_candidate.ps1` completes without `-SkipTests`.
- [ ] `scripts/qualify_windows.ps1` passes on Windows 11.
- [ ] install/upgrade/uninstall-reinstall behavior remains user-scoped and rollback-safe.
- [ ] startup task remains current-user/limited-run-level.
- [ ] dashboard remains loopback-only by default and renders without runtime errors.
- [ ] doctor/diagnose passes and SQLite quick check is healthy.
- [ ] evidence chain/signatures verify.
- [ ] Defender integration remains read-only.
- [ ] default process collection exercises the ransomware/evasion regex path without `NameError` or other parser failure.
- [ ] optional outbound-connection collection can be enabled and remains bounded/keyed/private.
- [ ] failed-logon collection uses installation-keyed source/account identities and persists no raw source/user.
- [ ] persistence collection parses registry/task/service rows produced by the shipped PowerShell command and persists no raw command/account value.
- [ ] privacy inspection confirms no raw process command lines, authentication source IPs/usernames, or sensitive persistence contents are persisted by the corrected v0.5 paths.
- [ ] high-signal event remains visible even if a prior lower-risk finding for that subject had been suppressed.
- [ ] no unexpected collector capability regression from the v0.4 Windows 11 baseline.

## Debian 12 qualification

On the exact candidate SHA:

```text
./scripts/validate_release.sh
```

Also confirm:

- [ ] Debian 12 service/install path remains observation-only.
- [ ] doctor/diagnose and local database/evidence verification pass.
- [ ] SSH credential-spray collection preserves installation-keyed source/user pseudonymization.
- [ ] optional outbound destinations use installation-keyed identity and raw addresses remain absent.
- [ ] Linux parent/child behavioral markers operate without persisting raw arguments.
- [ ] high-signal suppression bypass works without making lower-specificity administrative context unsuppressible.
- [ ] optional Docker/connection collectors fail as warnings when unavailable rather than confirmed threats.
- [ ] reboot/service recovery remains healthy.

## Safety gates

The exact candidate must preserve:

- [ ] `actions_executed == 0`;
- [ ] `executable_proposals == 0`;
- [ ] dashboard bind is `127.0.0.1` by default;
- [ ] cloud upload is disabled;
- [ ] public listener is disabled by default;
- [ ] automatic remediation is disabled;
- [ ] no file quarantine/deletion path exists;
- [ ] no process/service termination path exists;
- [ ] no firewall/host-isolation path exists;
- [ ] no arbitrary command execution path exists.

## Deterministic release package

Windows build:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_release_candidate.ps1
```

Linux validation:

```text
./scripts/validate_release.sh
```

Required package evidence:

- [ ] release candidate built twice with identical SHA-256;
- [ ] final archive name is `quietward-v0.5.0-alpha.1-source.zip`;
- [ ] checksum sidecar matches the final archive;
- [ ] `scripts/verify_release_bundle.py` returns PASS;
- [ ] archive manifest matches every packaged file/hash/size;
- [ ] archive includes `docs/releases/v0.5.0-alpha.1.md` and `docs/V05_RELEASE_CORRECTIONS.md`;
- [ ] archive includes the v0.5 changelog entry;
- [ ] archive contains no runtime databases, logs, keys, host evidence, scanner databases, qualification output or private machine paths.

## Supported-platform statement

Only after the v0.5 platform reruns above pass:

- [ ] Windows 11 may remain listed as qualified for the experimental alpha.
- [ ] Debian 12 may remain listed as qualified for the experimental alpha.
- [ ] Windows 10 remains not independently qualified.
- [ ] macOS remains not independently qualified.
- [ ] other Linux distributions remain experimental/not advertised as supported.

## Repository/legal/marketing review

- [ ] MIT license, SECURITY, support/contribution/code-of-conduct/privacy documentation and changelog remain present.
- [ ] final candidate diff reviewed for secrets, private host data and machine-specific paths.
- [ ] marketing uses `docs/V05_MARKETING_KIT.md` and keeps **experimental alpha** language.
- [ ] no claim of enterprise EDR replacement, breach prevention, autonomous remediation or zero false positives.
- [ ] GitHub private-vulnerability reporting/security settings reviewed before publication.
- [ ] professional trademark review completed if commercial distribution requires it.

## Publication gate

Only after every required item above is recorded PASS on the same candidate SHA:

- [ ] review/merge the v0.5 candidate into `main` with explicit owner authorization;
- [ ] create tag `v0.5.0-alpha.1`;
- [ ] publish only the verified deterministic source archive and checksum;
- [ ] publish limitations and observation-only safety language;
- [ ] keep host-specific qualification evidence/runtime state private.

Any unchecked required qualification item blocks publication.
