# QuietWard Guided Incident Response — vNext

This update increases practical incident-response value while preserving QuietWard's observation-only security boundary.

## Goal

Turn a high-confidence QuietWard finding into a structured, privacy-preserving response profile that QuietWard Response can immediately use to guide analyst triage.

QuietWard remains responsible for detection, correlation, scoring, evidence provenance, and sanitized one-way handoff. QuietWard Response remains the only component that may own future remediation authority.

## Phase 1 — Guided response context

Status: implementation started on `feature/guided-incident-response-vnext`.

QuietWard handoffs add a versioned, coarse response profile:

- `response_priority`: `routine`, `elevated`, or `urgent`
- `evidence_strength`: `limited`, `corroborated`, or `strong`
- `recommended_playbook`: an allowlisted investigation family
- `investigation_hints`: bounded read-only investigation hints
- existing keyed subject/finding identities and evidence-chain provenance remain intact

The handoff must never carry executable authority, raw remediation targets, commands, raw private subjects, or a mechanism for Response to control the QuietWard process.

## Phase 2 — One-click incident triage bundle

Response should add an analyst-approved `collect_incident_triage_bundle` action that composes its existing bounded host, process, and platform-supported network diagnostics into one signed result.

Requirements:

- parameterless and allowlisted
- outward-polling Response agent only
- no shell execution
- no raw command lines, arbitrary paths, or raw remote addresses
- capability-aware by operating system
- partial results explicitly identify unsupported/skipped components
- result is incident-bound, audited, and replay-safe

## Phase 3 — Evidence-bound containment in Response

Only after Phase 2 is fully qualified should Response gain real containment actions. QuietWard must remain observation-only.

Candidate actions:

- quarantine a previously observed file
- terminate a previously observed process
- disable a previously observed persistence entry
- restore a quarantined file

Every containment action must be bound to signed evidence captured before approval. At execution time Response must revalidate the target identity and fail closed if it changed. No arbitrary PID, path, command, address, or free-form target fields should be accepted from the analyst UI or QuietWard handoff.

## Phase 4 — Higher-value detection families

Once the response chain is trustworthy, expand QuietWard correlation for common endpoint threats:

1. ransomware-like rapid file mutation plus recovery/backup tampering
2. credential-access behavior around browser/session/credential stores
3. persistence changes correlated with newly created executables or suspicious process ancestry
4. living-off-the-land execution correlated with network or persistence activity
5. suspicious process + network + file sequences that individually appear low confidence

These detectors should produce evidence-backed findings and response profiles, not autonomous remediation.

## Release gates

- observation-only QuietWard invariants remain enforced
- privacy-leak tests cover every new handoff field
- malformed response context fails closed
- deterministic output for identical input evidence
- Response accepts only allowlisted context values
- response actions remain typed, capability-gated, approval-bound, and audited
- no generic shell or arbitrary command capability
- joint end-to-end tests cover QuietWard finding -> sanitized handoff -> incident -> recommendation -> approved diagnostic -> signed result
