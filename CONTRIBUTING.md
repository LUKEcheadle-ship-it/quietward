# Contributing to QuietWard

QuietWard welcomes focused, reviewable contributions that make local defensive monitoring easier to use while preserving the observation-only security boundary.

## Good places to start

You do **not** need to work on detection internals to contribute. Useful starter areas include:

- documentation and first-run clarity;
- dashboard usability and accessibility;
- sanitized synthetic fixtures;
- parser and regression tests;
- installer diagnostics;
- performance measurement;
- clearer finding/reason wording;
- Windows/Debian portability fixes.

See `docs/COMMUNITY_ROADMAP.md` for the current product direction.

## Development

Requires Python 3.11 or newer. The runtime has no mandatory third-party Python dependencies.

Before touching host collection, you can run the safe synthetic demo:

```bash
python scripts/quick_demo.py
```

Run the repository test/compile gates before opening a PR:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python -m compileall -q src tests scripts
```

## Pull requests

Keep changes focused and explain:

1. the user or engineering problem;
2. the data the change reads or stores;
3. failure behavior;
4. security/privacy impact;
5. tests added or run.

Add tests for privacy, first-run baselines, restart behavior, bounded resources, evidence integrity, and zero executed actions when relevant.

## Observation-only boundary

Do not casually add automatic quarantine, deletion, process termination, service control, firewall changes, host isolation, package installation, scanner updates, cloud telemetry, public listeners, arbitrary shell execution, or `sudo` use.

Any proposal that changes that boundary requires a separately reviewed threat-model and release decision rather than being slipped into an ordinary feature PR.

Never commit malware samples, credentials, host logs, runtime databases, raw process arguments, raw IP inventories, authorized keys, scanner databases, private qualification reports, or model inputs derived from private hosts.

## Security issues

Follow `SECURITY.md`. Do not disclose vulnerabilities, exploit details, secrets, or real incident evidence in public issues or pull requests.
