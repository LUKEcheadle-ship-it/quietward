# QuietWard v0.5.0-alpha.1 release checklist

Candidate branch: `feature/detection-hardening-v05`

Package version: `0.5.0a1`

This checklist is for the v0.5 detection-hardening release candidate. The prior v0.4 Windows 11/Debian 12 qualification is useful baseline evidence but **does not substitute for rerunning the v0.5 gates on the exact release SHA**.

Do not mark QuietWard stable or production-ready.

## Exact candidate record

- [ ] Record the final candidate SHA.
- [ ] Confirm tracked working tree is clean at that SHA.
- [ ] Confirm `pyproject.toml` and `quietward.__version__` both report `0.5.0a1`.
- [ ] Confirm `CHANGELOG.md`, README and `docs/releases/v0.5.0-alpha.1.md` describe the same candidate.

## Detection/repository gate

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
- [ ] Response repository/code separation check;
- [ ] observation-only README/source contract;
- [ ] cross-subject same-host attack-chain tests;
- [ ] process/network corroboration tests;
- [ ] privacy-preserving credential-spray tests;
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
- [ ] dashboard remains loopback-only and renders without runtime errors.
- [ ] doctor/diagnose passes and SQLite quick check is healthy.
- [ ] evidence chain/signatures verify.
- [ ] Defender integration remains read-only.
- [ ] privacy inspection confirms no raw process command lines, authentication source IPs/usernames, or sensitive persistence contents are persisted by the new v0.5 paths.
- [ ] no unexpected collector capability regression from the v0.4 Windows 11 baseline.

## Debian 12 qualification

On the exact candidate SHA:

```text
./scripts/validate_release.sh
```

Also confirm:

- [ ] Debian 12 service/install path remains observation-only.
- [ ] doctor/diagnose and local database/evidence verification pass.
- [ ] SSH credential-spray collection preserves source/user pseudonymization.
- [ ] Linux parent/child behavioral markers operate without persisting raw arguments.
- [ ] optional Docker/connection collectors fail as warnings when unavailable rather than confirmed threats.
- [ ] reboot/service recovery remains healthy.

## Safety gates

The exact candidate must preserve:

- [ ] `actions_executed == 0`;
- [ ] `executable_proposals == 0`;
- [ ] dashboard bind is `127.0.0.1` by default;
- [ ] cloud upload is disabled;
- [ ] public listener is disabled;
- [ ] automatic remediation is disabled;
- [ ] no file quarantine/deletion path exists;
- [ ] no process/service termination path exists;
- [ ] no firewall/host-isolation path exists;
- [ ] no arbitrary command execution path exists;
- [ ] no QuietWard Response client/agent/action integration exists in this repository.

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
- [ ] archive includes `docs/releases/v0.5.0-alpha.1.md`;
- [ ] archive includes the v0.5 changelog entry;
- [ ] archive contains no runtime databases, logs, keys, host evidence, scanner databases, qualification output or private machine paths.

## Supported-platform statement

Only after the v0.5 platform reruns above pass:

- [ ] Windows 11 may remain listed as qualified for the experimental alpha.
- [ ] Debian 12 may remain listed as qualified for the experimental alpha.
- [ ] Windows 10 remains not independently qualified.
- [ ] macOS remains not independently qualified.
- [ ] other Linux distributions remain experimental/not advertised as supported.

## Repository/legal review

- [ ] MIT license, SECURITY, support/contribution/code-of-conduct/privacy documentation and changelog remain present.
- [ ] final candidate diff reviewed for secrets, private host data and machine-specific paths.
- [ ] GitHub private-vulnerability reporting/security settings reviewed before publication.
- [ ] professional trademark review completed if commercial distribution requires it.

## Publication gate

Only after every required item above is recorded PASS on the same candidate SHA:

- [ ] review/merge the v0.5 candidate into QuietWard `main` with explicit owner authorization;
- [ ] create tag `v0.5.0-alpha.1`;
- [ ] publish only the verified deterministic source archive and checksum;
- [ ] publish limitations and observation-only safety language;
- [ ] keep host-specific qualification evidence/runtime state private.

Any unchecked required qualification item blocks publication.
