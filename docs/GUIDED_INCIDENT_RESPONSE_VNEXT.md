# QuietWard Guided Incident Response — vNext

This update increases practical incident-response value while preserving QuietWard's observation-only security boundary.

## Combined release requirement

The paired QuietWard + QuietWard Response update **must not ship until every QuietWard finding family has a tested Response resolution path**. The Response repository owns a machine-readable resolution matrix and a final release gate that remains blocked while any category is unresolved.

QuietWard remains responsible for detection, correlation, scoring, evidence provenance, sanitized one-way handoff, and generation of opaque resolution-target identities. QuietWard Response remains the only component allowed to own endpoint remediation authority.

## Phase 1 — Guided response context

Status: implemented and verified in the October 13 paired review. This does not publish a new package or release.

QuietWard handoffs add a versioned, coarse response profile:

- `response_priority`: `routine`, `elevated`, or `urgent`
- `evidence_strength`: `limited`, `corroborated`, or `strong`
- `recommended_playbook`: an allowlisted investigation family
- `investigation_hints`: bounded investigation hints
- optional opaque `resolution_target_handle`
- existing keyed subject/finding identities and evidence-chain provenance remain intact

The resolution-target handle contains no raw path, PID, address, account identifier or command. It does not grant execution authority. Any future raw target material required for remediation must remain in private endpoint-local escrow rather than crossing the Response server boundary.

## Phase 2 — One-click incident triage bundle

Status: implemented in the paired Response source, with Windows/Linux and browser qualification recorded on October 13. A new packaged release is still separate.

Response has an analyst-approved `collect_incident_triage_bundle` action that composes bounded host, process, and platform-supported network diagnostics. Process observations can be converted into endpoint-local opaque evidence handles for later containment without accepting arbitrary process targets.

## Phase 3 — Complete resolution coverage

Status: the 12 declared category families have tested, human-executed guided recovery and escalation paths. The October 13 paired Response review passed the executable category gate on Windows and Ubuntu. This **does not** mean every category has an automated remediation executor or that a new vNext release has been published.

The existing Response source also contains an evidence-bound process-containment action with explicit analyst approval, same-incident/host/agent provenance, execution-time identity revalidation, and protected-target checks. This is not an arbitrary process termination facility.

For the other categories, Response uses named independent approval, concrete category-specific recovery checkpoints, existing external ticket/evidence references, independent fresh verification, and accountable escalation. Operators execute the approved runbooks using their own authorized tools; Response does not execute the notes, validate external artifacts, or mutate the endpoint on their behalf.

The broader automatic-executor roadmap remains unimplemented in this release line:

- file quarantine and restore
- persistence disable/removal
- network containment
- identity/session recovery
- container/workload containment
- vulnerability remediation
- evidence-integrity recovery
- operational recovery

Generic-security findings must be routed to an actual supported category workflow; a placeholder such as "investigate manually" cannot satisfy resolution coverage. See the companion [guided recovery contract](https://github.com/LUKEcheadle-ship-it/quietward-response/blob/main/docs/GUIDED_RECOVERY_WORKFLOWS.md).

## Phase 4 — Higher-value detection families

Any new finding family must have a tested, concrete Response resolution or guided-recovery path before that detector is released. Potential future detection work includes:

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

## Current status

The October 13 paired review produced merged QuietWard source `1353dc37bc6e57bdd6fbb74c0e2a737235be33ea` and Response source `c05246e68bf2da9a986f3b64f9a2e01a89028402`. The [Response guided recovery qualification](https://github.com/LUKEcheadle-ship-it/quietward-response/actions/runs/38439060669) passed its 12-category recovery/escalation contracts on Windows and Ubuntu and its real multi-analyst browser check. Those are reviewed-source test receipts, not a signed formal release certificate.

**No paired vNext versioned release or expanded automatic remediation claim is authorized by this document.** Formal release qualification still requires exact-release-source reruns, target-host/install/upgrade/uninstall review, artifact integrity and privacy checks, and an explicit publication decision. QuietWard remains observation-only; the newer recovery workflows are explicitly human-executed and evidence-attested.
