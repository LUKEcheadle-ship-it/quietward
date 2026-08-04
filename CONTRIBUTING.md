# Contributing

QuietWard welcomes focused, reviewable contributions that preserve the observation-only security boundary.

## Development

Requires Python 3.11 or newer. The runtime has no mandatory third-party Python dependencies.

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python -m compileall -q src tests scripts
```

## Pull requests

Keep changes small and explain the threat model, data handled, failure behavior, and tests. Add tests for privacy, first-run baselines, restart behavior, bounded resources, and zero executed actions when relevant.

Do not add automatic quarantine, deletion, process termination, service control, firewall changes, package installation, scanner updates, cloud telemetry, public listeners, arbitrary shell execution, or `sudo` use without a separately reviewed design and release boundary.

Never commit malware samples, credentials, host logs, runtime databases, raw process arguments, raw IP inventories, authorized keys, scanner databases, private qualification reports, or model inputs derived from private hosts.

## Security issues

Follow `SECURITY.md`; do not disclose vulnerabilities in public issues or pull requests.
