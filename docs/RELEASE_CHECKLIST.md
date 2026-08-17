# Release checklist

Candidate: `v0.4.0-alpha.2`

This checklist separates completed product qualification from final publication actions. Do not mark the project stable or production-ready.

## Source gates

- [x] Windows 11 unit suite passed on the final candidate: 158 run, 153 passed, 0 failed, and 5 expected platform-dependent skips.
- [x] Python source, tests and scripts compiled on the Windows qualification host.
- [x] Public-release audit reported zero blockers on the Windows qualification host.
- [x] Supported Windows current-user installation, in-place upgrade and native qualification passed.
- [x] Doctor/diagnose passed; SQLite quick check returned `ok`.
- [x] Evidence chain and signatures verified.
- [x] Privacy review found no raw process arguments, addresses or persistence labels in persisted output.
- [x] Debian 12 corrected alpha evidence was reviewed, including controlled scenarios, privacy, evidence integrity, extended operation and successful reboot recovery.
- [x] Reran compilation, unit tests, release audit and native installer parsing on the final QuietWard candidate.
- [x] Built the release candidate twice and confirmed identical SHA-256 values.
- [x] Verified the final archive using `scripts/verify_release_bundle.py`.
- [x] Recorded the final commit, archive name, size and SHA-256 in the pull-request qualification record.

## Safety gates

- [x] `actions_executed == 0`.
- [x] `executable_proposals == 0`.
- [x] Dashboard binds to `127.0.0.1` by default.
- [x] Cloud upload is disabled.
- [x] Public listener is disabled.
- [x] Automatic remediation is disabled.
- [x] Microsoft Defender integration is read-only and does not start scans or change settings.
- [x] Windows startup task uses the current user with limited run level.

## Supported-platform statement

- [x] Windows 11 is qualified for the experimental alpha.
- [x] Debian 12 is qualified for the experimental alpha.
- [x] Windows 10 is not advertised as qualified.
- [x] Other Linux distributions are not advertised as supported.

## Repository and legal gates

- [x] MIT license, security policy, support policy, contribution guide, code of conduct, privacy documentation and changelog are present.
- [x] The unnecessary standalone NOTICE disclaimer was removed.
- [x] Runtime databases, qualification reports, keys, host logs and private machine evidence remain uncommitted.
- [x] Reviewed the final release-candidate diff for secrets and machine-specific paths.
- [ ] Confirm private vulnerability reporting and repository security settings before public visibility.
- [ ] Complete final professional trademark review if the project will be commercialized at scale.

## Publication gates

- [ ] Merge the reviewed QuietWard release-candidate PR.
- [ ] Create annotated or signed tag `v0.4.0-alpha.2`.
- [ ] Publish only the verified deterministic source archive and checksum.
- [ ] Change repository visibility only after explicit owner authorization.
- [ ] Publish the alpha announcement with limitations and observation-only safety language.
- [ ] Keep qualification evidence, runtime state, scanner data and host-specific reports private.
