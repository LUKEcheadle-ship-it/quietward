# QuietWard security model

## Trust order

1. Normalized deterministic collector and scanner evidence.
2. Deterministic risk scoring and correlation.
3. Optional tiny specialist scoring, limited to a 20% blend on non-authoritative evidence.
4. Optional localhost micro-LLM explanations.
5. Human review.

Authoritative ClamAV and YARA detections cannot be downgraded by the tiny model. Neither model can execute or authorize an action.

## Prohibited behavior

QuietWard contains no file quarantine, deletion, process termination, service control, firewall mutation, host isolation, package installation, signature update, cloud upload, public listener, shell execution or `sudo` execution path.

## Privacy

Raw process arguments, SSH source addresses, Docker IDs, journal messages, YARA matched strings, Trivy descriptions/references and full scanner outputs are not persisted. The database contains normalized bounded contracts and pseudonymous or hashed identifiers.

## Scanner execution

Scanner commands are assembled from typed configuration. Targets and rule/data paths must be absolute. No arbitrary command field exists. Subprocesses run with `shell=False`, bounded output, timeouts, minimal environment, no stdin and updater flags disabled or omitted.
# Privileged telemetry helper (Linux validation candidate)

The optional `quietward-telemetry-helper` is a local-only, root-owned process
event producer.  It subscribes to Linux proc-connector lifecycle metadata and
immediately converts it into bounded, normalized records.  It has no network
listener, no action interface, no command interface, and no persistent event
database.  The normal QuietWard service remains unprivileged and consumes only
those records through `/run/quietward/telemetry.sock`, owned by `root` and the
QuietWard service group with mode `0660`.

The helper retains a bounded in-memory ring (4096 records).  It does not
persist command lines: arguments are read only long enough to derive the
`encoded_shell_chain` boolean and an optional SHA-256 hash.  The unit restricts
address families to `AF_UNIX` and `AF_NETLINK`, bounds memory/tasks/files, uses
`NoNewPrivileges`, and limits capabilities to `CAP_NET_ADMIN`,
`CAP_DAC_READ_SEARCH`, `CAP_NET_RAW` (TCP SYN metadata only; packet payloads
are discarded), and `CAP_CHOWN` (the latter only sets the socket group).
`PrivateTmp` is deliberately disabled for this unit because its configured
event source monitors the real host `/tmp`; the remaining filesystem sandbox
prevents writes outside the runtime directory.
It performs observation only; it cannot run remediation, mutate accounts,
alter packages/firewalls, or accept network requests.
