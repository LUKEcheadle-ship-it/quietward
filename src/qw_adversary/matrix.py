from __future__ import annotations

from .models import AttackCase


CASES: tuple[AttackCase, ...] = (
    AttackCase("AUTH-001", "protocol-auth", "Missing authentication headers", "Response rejects the request before business logic."),
    AttackCase("AUTH-002", "protocol-auth", "Wrong key identifier", "Response rejects a validly shaped request with the wrong key ID."),
    AttackCase("AUTH-003", "protocol-auth", "Body tamper after signing", "Body mutation invalidates the HMAC signature."),
    AttackCase("AUTH-004", "protocol-auth", "Path/query tamper after signing", "Target mutation invalidates the HMAC signature."),
    AttackCase("AUTH-005", "protocol-auth", "Stale timestamp", "Requests outside the configured replay window are rejected."),
    AttackCase("AUTH-006", "protocol-auth", "Future timestamp", "Future requests outside the replay window are rejected."),
    AttackCase("AUTH-007", "protocol-auth", "Nonce replay", "A valid nonce is single-use even if later business validation fails."),
    AttackCase("AUTH-008", "protocol-auth", "Event UUID content conflict", "Reusing an accepted event ID with different content is rejected as an integrity conflict."),
    AttackCase("AGENT-001", "agent-lifecycle", "Disabled agent sends new telemetry", "Disabled credentials cannot submit new telemetry."),
    AttackCase("AGENT-002", "agent-lifecycle", "Disabled agent requests new work", "Disabled credentials cannot retrieve new or pre-execution work."),
    AttackCase("AGENT-003", "agent-lifecycle", "Disabled executing-agent reconciliation", "Only the exact already-executing lifecycle may reconcile."),
    AttackCase("APPROVAL-001", "approval-policy", "Approval identity spoof characterization", "Document that X-Actor-ID is development-grade and not an authentication boundary.", documented_limitation=True),
    AttackCase("APPROVAL-002", "approval-policy", "Approval overwrite", "A second decision cannot overwrite the original approval/rejection identity."),
    AttackCase("APPROVAL-003", "approval-policy", "Closed incident action", "Resolved/dismissed incidents cannot create or dispatch actions."),
    AttackCase("APPROVAL-004", "approval-policy", "Expired action or approval", "Expired work cannot dispatch or be revived."),
    AttackCase("APPROVAL-005", "approval-policy", "Wrong host or agent binding", "Action target must match the incident and approved agent."),
    AttackCase("RESULT-001", "action-result", "Result from wrong agent", "A result signed by another credential is rejected."),
    AttackCase("RESULT-002", "action-result", "Terminal result skips executing", "Lifecycle cannot jump directly to terminal state."),
    AttackCase("RESULT-003", "action-result", "Conflicting duplicate terminal result", "Only byte/structure-equivalent terminal retries are accepted."),
    AttackCase("RESULT-004", "action-result", "Result after cancellation", "Cancelled pre-execution work cannot be revived by a result."),
    AttackCase("SERVER-001", "malicious-response", "Unknown action type", "QuietWard endpoint rejects action types outside its hard-coded allowlist."),
    AttackCase("SERVER-002", "malicious-response", "Command-like fields", "QuietWard endpoint rejects shell/path/service/PID-style injected fields."),
    AttackCase("SERVER-003", "malicious-response", "Non-empty parameters", "The v1 demo action rejects all parameters."),
    AttackCase("SERVER-004", "malicious-response", "Wrong host or agent target", "Endpoint rejects actions not addressed exactly to itself."),
    AttackCase("SERVER-005", "malicious-response", "Stale action expiry", "Endpoint refuses expired dispatches."),
    AttackCase("STATE-001", "endpoint-state", "Corrupt event outbox", "Integration fails closed without erasing queued evidence; local monitoring continues."),
    AttackCase("STATE-002", "endpoint-state", "Corrupt action ledger", "Integration fails closed rather than treating history as unused."),
    AttackCase("STATE-003", "endpoint-state", "Corrupt demo state", "Malformed security-relevant fixture state cannot be silently reset."),
    AttackCase("AUDIT-001", "audit", "Audit row content mutation", "Hash-chain verification detects modified historical content."),
    AttackCase("AUDIT-002", "audit", "Partial hash-chain mutation", "Startup/API verification fails closed on a broken existing chain."),
    AttackCase("AUDIT-003", "audit", "Full chain recomputation", "Characterize documented limit: an administrator can rewrite records and hashes consistently.", documented_limitation=True),
    AttackCase("AUDIT-004", "audit", "Audit suffix deletion", "Characterize documented limit: local hash chaining alone cannot prove a deleted suffix.", documented_limitation=True),
    AttackCase("CONC-001", "concurrency", "Supported single-worker stress", "Concurrent requests remain consistent inside the qualified one-worker runtime."),
    AttackCase("CONC-002", "concurrency", "Unsupported multi-worker characterization", "Do not score unsupported multi-worker behavior as a v1 regression.", documented_limitation=True),
    AttackCase("DATA-001", "data-hardening", "Enrollment response caching", "One-time enrollment secret response is marked no-store/no-cache."),
    AttackCase("DATA-002", "data-hardening", "Secret/log contamination", "Agent credentials do not appear in normal application logs."),
    AttackCase("DATA-003", "data-hardening", "Rate-limit absence characterization", "Rate limiting is a documented post-v1 hardening item.", documented_limitation=True),
    AttackCase("DATA-004", "data-hardening", "Evidence redaction absence characterization", "Field-level redaction/encryption is a documented post-v1 hardening item.", documented_limitation=True),
)


def validate_matrix() -> None:
    ids = [case.case_id for case in CASES]
    if len(ids) != len(set(ids)):
        raise ValueError("attack case IDs must be unique")
    if any(case.destructive for case in CASES):
        raise ValueError("v0.1 matrix must remain non-destructive")
