# QuietWard Guided Incident Response — vNext

This update increases practical incident-response value while preserving QuietWard's observation-only security boundary.

## Combined release requirement

The paired QuietWard + QuietWard Response update **must not ship until every QuietWard finding family has a tested Response resolution path**. The Response repository owns a machine-readable resolution matrix and a final release gate that remains blocked while any category is unresolved.

QuietWard remains responsible for detection, correlation, scoring, evidence provenance, sanitized one-way handoff, and generation of opaque resolution-target identities. QuietWard Response remains the only component allowed to own endpoint remediation authority.

## Phase 1 — Guided response context

Status: implemented; qualification pending.

QuietWard handoffs add a versioned, coarse response profile:

- `response_priority`: `routine`, `elevated`, or `urgent`
- `evidence_strength`: `limited`, `corroborated`, or `strong`
- `recommended_playbook`: an allowlisted investigation family
- `investigation_hints`: bounded investigation hints
- optional opaque `resolution_target_handle`
- existing keyed subject/finding identities and evidence-chain provenance remain intact

The resolution-target handle contains no raw path, PID, address, account identifier or command. It does not grant execution authority. Any future raw target material required for remediation must remain in private endpoint-local escrow rather than crossing the Response server boundary.

## Phase 2 — One-click incident triage bundle

Status: implemented in the paired Response feature branch; qualification pending.

Response has an analyst-approved `collect_incident_triage_bundle` action that composes bounded host, process, and platform-supported network diagnostics. Process observations can be converted into endpoint-local opaque evidence handles for later containment without accepting arbitrary process targets.

## Phase 3 — Complete resolution coverage

Status: in progress and release-blocking.

The first real containment family is implemented in the Response feature branch:

- evidence-bound process termination
- analyst approval required
- no arbitrary PID
- same-incident/host/agent provenance required
- execution-time process identity revalidation
- protected system processes fail closed

The combined release remains blocked until the remaining finding families have real resolution paths, including:

- file quarantine and restore
- persistence disable/removal
- network containment
- identity/session recovery
- container/workload containment
- vulnerability remediation verification
- evidence-integrity recovery
- operational recovery
- generic-security fallback routing to a concrete resolution family

A category may use a safe typed Response action or a tested guided escalation/recovery workflow when universal automatic mutation would be unsafe. A generic manual-investigation placeholder does not count as complete coverage.

## Phase 4 — Higher-value detection families

Only after the resolution chain is complete should QuietWard expand detection for additional common endpoint threats:

1. ransomware-like rapid file mutation plus recovery/backup tampering
2. credential-access behavior around browser/session/credential stores
3. persistence changes correlated with newly created executables or suspicious process ancestry
4. living-off-the-land execution correlated with network or persistence activity
5. suspicious process + network + file sequences that individually appear low confidence

New detectors should not be released unless Response can resolve or explicitly escalate the resulting finding family under the same release-coverage standard.

## Release gates

- observation-only QuietWard invariants remain enforced
- privacy-leak tests cover every new handoff field
- legacy handoffs remain upgrade-compatible
- malformed response/remediation handles fail closed
- deterministic output for identical input evidence
- Response accepts only allowlisted context values
- response actions remain typed, capability-gated, approval-bound, evidence-bound where needed, and audited
- no generic shell or arbitrary command/PID/path/address capability
- joint end-to-end tests cover finding -> sanitized handoff -> incident -> triage -> approval -> action -> signed result -> audit
- paired Response resolution-coverage gate passes with zero unresolved QuietWard categories
