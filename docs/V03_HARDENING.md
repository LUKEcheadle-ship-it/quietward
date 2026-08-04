# QuietWard v0.3 hardening

QuietWard v0.3 extended the observation-only candidate without adding containment authority.

## Added coverage

- account and privileged-group membership changes;
- SSH `authorized_keys`, cron, systemd service/timer, sudoers fragment and shell-startup persistence changes;
- Docker privileged mode, host network/PID/IPC, Docker socket and sensitive host mounts, dangerous capabilities, missing no-new-privileges, restart loops and unhealthy status;
- QuietWard source, configuration, model, service-unit and explicitly configured path integrity;
- tamper-evident per-cycle evidence chaining;
- finding acknowledgment, resolution, expected-state marking, temporary suppression, reopening and analyst notes.

## Suppression boundary

Suppression rules match an exact normalized subject. They affect QuietWard alert handling only and never change the host. The following evidence cannot be suppressed:

- ClamAV malware signatures;
- YARA matches;
- QuietWard self-integrity changes;
- evidence-chain failures.

```bash
quietward incident --config ~/.config/quietward/config.json list
quietward incident --config ~/.config/quietward/config.json acknowledge FINDING_ID --note "investigating"
quietward incident --config ~/.config/quietward/config.json suppress FINDING_ID --minutes 60 --note "planned maintenance"
quietward incident --config ~/.config/quietward/config.json expected FINDING_ID --note "approved persistent service"
quietward incident --config ~/.config/quietward/config.json resolve FINDING_ID
quietward incident --config ~/.config/quietward/config.json reopen FINDING_ID
quietward incident --config ~/.config/quietward/config.json verify-chain
```

## Privacy

Raw authorized keys, cron contents, service-unit contents, process arguments, source addresses, Docker IDs and scanner output are not persisted. Persistence artifacts are represented by hashes, bounded metadata and risk markers.

## Evidence chain

Each persistent cycle records the previous chain hash and a hash of the normalized cycle payload. Verification detects row deletion, reordering or payload modification within the retained chain. Optional local HMAC signing strengthens this evidence but does not replace an external audit archive.

## Acceptance boundary

Hardening changes require actual-host qualification with extra attention to initial persistence baseline size, Docker permission behavior, expected-task false positives, self-integrity stability, suppression expiration and evidence-chain verification across restarts and retention cycles.
