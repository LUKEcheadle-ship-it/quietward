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
