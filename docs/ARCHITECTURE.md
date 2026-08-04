# QuietWard architecture

## Product boundary

QuietWard is a separate cybersecurity product and repository. It reuses Forge-style contracts, orchestration, safety gates, evaluation discipline, optional micro-LLM workers, and offline-first design. It does not place privileged scanner daemons or containment logic inside the main Forge system.

## Hybrid pipeline

```text
Host and container observations
        |
        v
Read-only collectors + deterministic scanners
        |
        v
Normalized SecurityEvent contracts
        |
        v
Deterministic scoring + bounded tiny specialist model
        |
        v
Incident correlation + non-executable ActionProposal
        |
        v
Optional localhost micro-LLM explanation
        |
        v
Human review
```

Scanner and collector evidence is authoritative. The tiny model may only rank or blend non-authoritative evidence and cannot downgrade ClamAV or YARA detections. The optional micro-LLM explains findings and cannot authorize or execute actions.

## Read-only collection

The Debian collector captures privacy-reduced process, listening-socket, authentication, Docker, and sensitive-file state. It uses exact command families for `ps`, `ss`, `journalctl`, and `docker ps`, with no shell, sudo, package installation, mutation, or permission escalation. Raw process arguments, SSH addresses, Docker IDs, and journal messages are not persisted.

The first snapshot establishes a baseline and emits no process, port, container, or file-change event. Later cycles compare against the persisted snapshot.

## Scanner boundary

ClamAV, YARA, Trivy, and debsecan adapters normalize bounded reports. Controlled execution wrappers use typed configuration, absolute targets, `shell=False`, no stdin, timeouts, bounded output, no updater command, offline Trivy flags, and an explicit local-file-only debsecan source. Scanner data freshness is observed but never updated by QuietWard.

## Persistence and service

QuietWard uses SQLite with WAL mode and transactional writes for cycles, snapshots, events, findings, proposals, alerts, and scanner runs. Retention is bounded by age and record count. A single-instance user service writes private health and alert files atomically, handles SIGTERM promptly, and exits after a configurable consecutive-failure limit.

## Dashboard

The dashboard is read-only. Loopback is the default. A private RFC1918 or Tailscale bind requires an explicit opt-in and a private token file. Public binding and mutation methods are rejected.

## Model layers

The packaged tiny model is a compact logistic priority model trained from an abstract synthetic bootstrap dataset. It is optional, reproducible, and explicitly not target-host qualified. Its score is capped to a 20% blend for non-authoritative evidence and can never weaken authoritative detections.

The optional Forge/Ollama explanation layer is localhost-only, validates strict JSON, falls back deterministically, and always returns `action_authorized: false`.

## Current source status

Implemented:

- safe configuration and observation-only policy;
- read-only host collection and baseline diffing;
- scanner adapters, controlled execution, and freshness checks;
- transactional local storage and retention;
- persistent service, health reporting, and private alert spool;
- tiny model runtime, trainer, artifact, and hybrid scorer;
- optional local micro-LLM explanation;
- read-only dashboard;
- zero-dependency user installation, systemd service, qualification, operations, and clean removal;
- restart, retention, privacy, scanner, model, dashboard, and bounded soak tests.

Containment remains intentionally absent.
