# QuietWard 0.6.0-alpha.1 — final release gates

**Status: SOURCE CANDIDATE ONLY; NOT A PUBLISHED PRERELEASE.**

The current package version is `0.6.0a1`, with display tag `v0.6.0-alpha.1`. The publicly published prerelease remains `v0.5.0-alpha.1`. The source on `main` includes the versioned observation-only handoff and newer guided-response context. These do not authorize any QuietWard endpoint action.

## Evidence already recorded

- Current source and package metadata agree on version `0.6.0a1`; matching release notes and changelog exist.
- Public source and deterministic bundle validators are checked in. The current bundle builder has manifest hashes and rejects unsafe source paths.
- The companion QuietWard Response review passed Linux/Windows source tests, 12-category *human-attested* guided recovery contracts and paired integration. These prove software behavior, **not native 0.6 installer qualification on the exact final Windows 11 and Debian 12 target hosts**.
- QuietWard remains observation-only (`actions_executed == 0`, `executable_proposals == 0`). Response, not QuietWard, owns analyst-approved actions.

## Required before publication

Use the **same selected immutable source SHA** throughout. A documentation or versioning change after qualification changes that release SHA and requires reconciling the evidence.

- [ ] Select and record exact commit SHA, branch/tag, version, license, public release notes, limitations, README and security/privacy documents.
- [ ] Run `python3 scripts/validate_migrated_release.py --root . --pretty` (full tests, safety checks, public-source audit, deterministic double archive and verification) on that SHA. This should have no skipped required checks.
- [ ] Run `bash scripts/validate_release.sh` and record verified archive hash. If using Windows, use the strict `scripts/build_release_candidate.ps1` instead of bypassing its tests.
- [ ] **Native Windows 11, exact SHA:** test fresh install, upgrade from supported prior version, `scripts/qualify_windows.ps1`, scheduled-task/dashboard state, persistence, uninstall and data-preserving rollback/recovery. Record signed or otherwise integrity-checked *private* operator evidence.
- [ ] **Native Debian 12, exact SHA:** test fresh user-service install, upgrade/migration, `scripts/qualify_target_host.sh`, status/dashboard, clean uninstall and data-preserving rollback/recovery. Record private operator evidence.
- [ ] Verify zero executed QuietWard actions/proposals, tamper-evident storage integrity, no unexpected cloud/network flow or privacy leak, allowed host-resource limits and no unsupported privileges.
- [ ] Review public diff and final archive for secrets, machine-specific paths, private data, binaries, user state, malformed manifest, wrong license/version or dangerous startup defaults.
- [ ] Confirm pinned QuietWard 0.6 ↔ Response paired-source acceptance on the selected revisions and describe which Response release is actually available.
- [ ] Explicit owner approval is on record (requested finishing/publication on October 15, 2026), but **authorization is conditional on every required gate passing**.
- [ ] Tag precisely the verified commit `v0.6.0-alpha.1`; publish a prerelease with the matching source archive, SHA-256 sidecar and appropriately qualified platform/limitation notes.
- [ ] Independently read back the published tag, archive size, hashes, provenance and release metadata, then mark [release issue #10](https://github.com/LUKEcheadle-ship-it/quietward/issues/10) complete.

## Non-negotiable exclusions

Do not introduce a GitHub Actions workflow into QuietWard to bypass its checked-in public-release gate. Do not claim that generic automatic remediation, Windows 10, macOS, Internet-facing protection, enterprise EDR or zero false positives were tested or supported. GitHub-hosted Windows Server runners do not replace **native Windows 11** evidence. Local host logs and credentials remain private; only sanitized results and source/build hashes may be published.

**Decision:** remain unpublished until the native Windows 11/Debian 12 and immutable-source gates are independently verified. 
