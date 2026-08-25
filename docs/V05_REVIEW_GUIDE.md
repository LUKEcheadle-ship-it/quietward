# QuietWard v0.5 approval review guide

Package version: `0.5.0a1`

This guide covers the combined v0.5.0-alpha.1 candidate: the approved low-overhead performance/lifecycle core plus the public detection/privacy hardening line.

## Review priorities

### 1. Observation-only boundary

Confirm zero executed actions and executable proposals; no arbitrary command field or generic executor; no process/service termination; no quarantine/deletion; no firewall or host-isolation mutation; and a read-only dashboard.

Run `scripts/audit_v05_safety.py` and the complete repository suite on the exact public candidate SHA.

### 2. Privacy boundary

Identity-bearing authentication/outbound paths must require installation-scoped privacy identities and must not persist raw source/destination addresses or usernames. Review the Windows/Linux address pseudonym tests and redacted incident export v2.

### 3. Suppression behavior

Confirm routine reviewed events can still be suppressed narrowly, prior-cycle context cannot broaden a suppression rule, and explicit high-signal behavior bypasses an older subject suppression rule.

### 4. Coverage/lifecycle correctness

A not-due or degraded domain must never count as proof that an incident disappeared. Verify source-aware resolution for process, listener, persistence, scanner and integrity incidents.

### 5. Detection logic

Review `correlation.py`, `scoring.py`, Linux/Windows collectors and parser tests for bounded cross-subject attack chains, process/network corroboration, credential spray without raw identities, high-confidence behavior floors, parent→child detections, and destructive/evasion markers with benign negative controls.

### 6. Performance architecture

Validate FAST separately from STANDARD/DEEP/MAINTENANCE. Targets are:

- mean FAST CPU <= 2% total CPU capacity;
- maximum RSS <= 100 MiB excluding optional external scanners/models;
- FAST p50 <= 500 ms;
- FAST p95 <= 1500 ms;
- analysis p95 <= 50 ms;
- at least five real FAST-only samples.

### 7. Release-tree cleanliness

The public release branch must not contain private development history, private approval packets, machine-specific runtime evidence, secrets, runtime databases, keys, or GitHub Actions workflows.

## Approval sequence

1. Private exact candidate passes native Windows runtime qualification.
2. Controlled private-to-public migration passes.
3. Migrated release gate passes.
4. Validated tree is replayed onto a clean public QuietWard release branch.
5. Exact public SHA passes complete tests, compilation, static safety audit, public-release audit and deterministic packaging.
6. Exact public SHA passes native Windows 11 and Debian 12 release qualification.
7. Release notes and marketing claims are reviewed against the evidence.
8. Only then merge/tag/prerelease publication and marketing are approved.

## Approval outcome

Use **APPROVE FOR RELEASE** only when the exact public release SHA has passed the packaging, platform and reviewer gates. Otherwise block publication.
