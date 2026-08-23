# QuietWard v0.5.0-alpha.1 reviewer guide

Candidate branch: `feature/detection-hardening-v05`

Package version: `0.5.0a1`

## What reviewers are evaluating

QuietWard is an offline-first, observation-only host security monitor. v0.5 is a detection-hardening release: it improves deterministic detection, correlation and privacy-preserving security context without adding host remediation.

The core release question is:

> Does v0.5 materially improve detection quality while preserving QuietWard's observation-only, privacy-conscious safety boundary?

## Review order

### 1. Safety boundary

Start with:

- `README.md`
- `docs/releases/v0.5.0-alpha.1.md`
- `docs/RELEASE_CHECKLIST.md`
- `scripts/verify_v05_detection.py`

Required invariants:

```text
actions_executed == 0
executable_proposals == 0
dashboard_bind == 127.0.0.1
cloud_upload == false
public_listener == false
```

QuietWard must not contain a process-kill, quarantine/delete, firewall, host-isolation, arbitrary-command or automatic-remediation path.

### 2. Detection logic

Focus files:

- `src/quietward/correlation.py`
- `src/quietward/scoring.py`
- `src/quietward/collectors/debian.py`
- `src/quietward/collectors/parsers.py`
- `src/quietward/collectors/windows_parsers.py`

Review for:

- bounded same-host cross-subject attack chains;
- process/network corroboration without over-grouping unrelated events;
- credential-spray recognition without raw username/source-IP persistence;
- narrow high-confidence behavior floors rather than broad heuristic escalation;
- parent→child detections with explicit negative controls;
- destructive/ransomware/evasion markers that do not match benign read/query operations.

### 3. Regression and false-positive coverage

Primary v0.5 suites:

- `tests/test_detection_hardening_v05.py`
- `tests/test_detection_adversarial_v05.py`
- `tests/test_high_signal_marker_correlation_v05.py`
- `tests/test_parent_child_detection_v05.py`
- `tests/test_linux_parent_child_parser_v05.py`
- `tests/test_process_network_corroboration_v05.py`
- `tests/test_windows_impact_evasion_v05.py`
- `tests/test_v05_detection_matrix_contract.py`

The release matrix is `docs/V05_DETECTION_REGRESSION_MATRIX.md`.

A test file existing is not qualification evidence; the exact candidate SHA must execute the release gate successfully.

## Reproduce the candidate gate

Install release-test dependencies:

```text
python -m pip install -e ".[release]"
```

Run:

```text
python scripts/verify_v05_detection.py
```

Linux release validation:

```text
./scripts/validate_release.sh
```

Windows release/package qualification:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_release_candidate.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\qualify_windows.ps1
```

The exact release SHA must be rerun on Windows 11 and Debian 12 before publication.

## Questions reviewers should answer

1. Are new HIGH-priority floors restricted to high-confidence evidence?
2. Can unrelated same-host activity be incorrectly collapsed into one attack chain?
3. Does credential-spray detection preserve the documented identity/address privacy boundary?
4. Do Windows process markers distinguish destructive actions from benign status/query commands?
5. Do ancestry detections have convincing false-positive controls?
6. Does any new code create a state-changing execution path?
7. Are the release notes and marketing claims supported by tests and implementation?

## Known limitations

- experimental alpha, not a replacement for professional EDR/endpoint protection;
- Windows 11 and Debian 12 require fresh v0.5 qualification before the release can claim support;
- Windows 10, macOS and other Linux distributions are not independently qualified;
- optional collector availability varies by platform/permissions;
- detection is deterministic and intentionally conservative rather than comprehensive malware prevention.

## Review decision

Approve for release only when:

- code review finds no safety/privacy regression;
- `scripts/verify_v05_detection.py` passes on the exact SHA;
- deterministic release packaging passes;
- Windows 11 qualification passes;
- Debian 12 qualification passes;
- `docs/RELEASE_CHECKLIST.md` is completed with evidence from that same SHA.
